# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The .ko (kernel-module) information line of a run pair.

A .ko is an ELF relocatable (``et_rel``); it is NOT a file subject and NOT in the completion
denominator (it carries no entry point the binary diff can align). Instead it is listed, read-only,
as a neutral information line: for a .ko whose content differs, which ELF *sections* differ; and
when any differing section is executable (``SHF_EXECINSTR``), the function-symbol names added /
removed / resized across all executable sections. A .ko held by one run only is listed as a module
added / removed.

Read at MCP-read time with pyelftools, in the MCP process — never during a scan, so no stamp moves.
Untrusted input: each file is read only inside its firmware root, only when its bytes match the
sha256 the scan recorded, and only up to a size limit; anything else, or any parse failure, reads
``unknown`` (never 0 / false). The text states mechanism only; it draws no conclusion.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from typing import Any

from treasure_map.lib.query.file_diff import AlignedFile, PairFiles, aligned_ko

# Above this a .ko is not parsed (reads ``unknown``): the largest .ko seen across the corpus is
# ~14.95 MB, so the limit clears every real module and still bounds a hostile file.
MAX_KO_BYTES = 32 * 1024 * 1024
# A page of the lists (ko_offset), in bytes of their JSON encoding: every list is cut at the same
# item, the most that fit, always one.
KO_PAGE_BYTES = 30_000
# A section whose bytes the file cannot hold (its offset + size run past the end) has this digest:
# it is neither the same nor different, and is listed under sections_unknown.
_UNREADABLE = "unknown"
_NOBITS = "SHT_NOBITS"
# The most function names any one list prints; a longer list gives its count and is truncated.
FUNC_NAME_CAP = 60

KO_NOTE = (
    "A .ko is an ELF relocatable kernel module: it carries no entry point a binary diff can align, "
    "so it is not a diff subject and not in the completion denominator. This is a read-only, "
    "neutral record of which ELF sections differ (sections_differ) and — when any differing "
    "section is executable — the function symbols one run has that the other does not "
    "(funcs_a_only / funcs_b_only) and those whose size differs (funcs_resized), across the "
    "executable sections. renamed = the same bytes under another path (paired by sha256); "
    "undetermined = a side recorded no sha256, so the two cannot be told apart (never one run "
    "holding it alone); a_only / b_only list the modules one run holds alone. A section that holds "
    "no file bytes (SHT_NOBITS) is compared by its size; one whose bytes run past the end of the "
    "file is listed under sections_unknown. unknown means the file could not be read as the scan "
    "hashed it, or is over the size limit, or did not parse; it never means 'no change'. The first "
    "page gives the counts; the lists are read with ko_offset."
)


def _exec_flag(section: Any) -> bool:
    try:
        from elftools.elf.constants import SH_FLAGS

        return bool(section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR)
    except Exception:  # a malformed flag field is not executable, by default
        return False


def _parse(root: str | None, path: str, expected_sha: str | None) -> tuple[str, Any]:
    """``("ok", info)`` for a parsed .ko, else ``("unknown", reason)``. ``info`` is
    ``{sections: {name: (digest, is_exec, size, sh_type)}, funcs: {name: size}}`` over the
    executable sections. Read-only; never raises."""
    if not root:
        return "unknown", "no_firmware_root"
    target = os.path.realpath(os.path.join(root, path))
    if os.path.commonpath([os.path.realpath(root), target]) != os.path.realpath(root):
        return "unknown", "outside_firmware_root"
    try:
        size = os.path.getsize(target)
    except OSError:
        return "unknown", "file_missing"
    if size > MAX_KO_BYTES:
        return "unknown", "over_size_limit"
    try:
        with open(target, "rb") as fh:
            data = fh.read()
    except OSError:
        return "unknown", "file_unreadable"
    if expected_sha is not None and hashlib.sha256(data).hexdigest() != expected_sha:
        return "unknown", "content_differs_from_scan"
    try:
        import io

        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection

        elf = ELFFile(io.BytesIO(data))
        sections: dict[str, tuple[str, bool, int, str]] = {}
        exec_idx: set[int] = set()
        for i, sec in enumerate(elf.iter_sections()):
            is_exec = _exec_flag(sec)
            if is_exec:
                exec_idx.add(i)
            sections[sec.name] = (
                _section_digest(data, sec),
                is_exec,
                int(sec["sh_size"]),
                str(sec["sh_type"]),
            )
        funcs: dict[str, int] = {}
        symtab = elf.get_section_by_name(".symtab")
        if isinstance(symtab, SymbolTableSection):
            for sym in symtab.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC" or not sym.name:
                    continue
                shndx = sym["st_shndx"]
                if isinstance(shndx, int) and shndx in exec_idx:
                    funcs[sym.name] = int(sym["st_size"])
    except Exception as exc:  # a hostile / truncated ELF must read unknown, not crash
        return "unknown", f"parse_failed:{type(exc).__name__}"
    return "ok", {"sections": sections, "funcs": funcs}


def _section_digest(data: bytes, sec: Any) -> str:
    """A section's comparison key, from the file bytes already read — never ``sec.data()``, which
    materialises what the header declares (a NOBITS section's zeros, a compressed section's
    decompressed size) whatever the file holds. NOBITS: its declared size alone (no file bytes).
    Otherwise the sha256 of the stored bytes ``data[sh_offset : sh_offset + sh_size]`` (a compressed
    section's are its compressed bytes), or ``unknown`` when that range runs past the file."""
    size = int(sec["sh_size"])
    if str(sec["sh_type"]) == _NOBITS:
        return f"nobits:{size}"
    offset = int(sec["sh_offset"])
    if offset < 0 or size < 0 or offset + size > len(data):
        return _UNREADABLE
    return hashlib.sha256(data[offset : offset + size]).hexdigest()


def _names(a: set[str], b: set[str]) -> dict[str, Any]:
    """A name-set difference as a count and (capped) list."""
    out: dict[str, Any] = {"count": len(a - b)}
    extra = sorted(a - b)
    out["names"] = extra[:FUNC_NAME_CAP]
    if len(extra) > FUNC_NAME_CAP:
        out["names_truncated"] = True
    return out


def _func_delta(fa: dict[str, int], fb: dict[str, int]) -> dict[str, Any]:
    b_only = _names(set(fb), set(fa))  # in run B's module, not run A's
    a_only = _names(set(fa), set(fb))  # in run A's module, not run B's
    resized_names = sorted(n for n in set(fa) & set(fb) if fa[n] != fb[n])
    resized: dict[str, Any] = {
        "count": len(resized_names),
        "names": resized_names[:FUNC_NAME_CAP],
    }
    if len(resized_names) > FUNC_NAME_CAP:
        resized["names_truncated"] = True
    return {"funcs_a_only": a_only, "funcs_b_only": b_only, "funcs_resized": resized}


def _content_entry(pf: PairFiles, af: AlignedFile) -> dict[str, Any]:
    oa, ia = _parse(pf.a.root, str(af.path_a), af.sha_a)
    ob, ib = _parse(pf.b.root, str(af.path_b), af.sha_b)
    entry: dict[str, Any] = {
        "path_a": af.path_a,
        "path_b": af.path_b,
        "paired_by": af.paired_by,
        "sha_a": af.sha_a,
        "sha_b": af.sha_b,
    }
    if oa != "ok" or ob != "ok":
        entry["sections_differ"] = "unknown"
        entry["unknown_reason"] = {"a": ia if oa != "ok" else None, "b": ib if ob != "ok" else None}
        return entry
    sa, sb = ia["sections"], ib["sections"]
    unknown = sorted(
        name for name in set(sa) & set(sb) if _UNREADABLE in (sa[name][0], sb[name][0])
    )
    differ = sorted(
        name
        for name in set(sa) | set(sb)
        if name not in unknown and (name not in sa or name not in sb or sa[name] != sb[name])
    )
    entry["sections_differ"] = differ
    if unknown:
        entry["sections_unknown"] = unknown
    exec_differ = [
        name for name in differ if (name in sa and sa[name][1]) or (name in sb and sb[name][1])
    ]
    if exec_differ:
        entry.update(_func_delta(ia["funcs"], ib["funcs"]))
    return entry


# The lists of the block, in the order a page gives them.
_LIST_KEYS = ("content_differs", "renamed", "undetermined", "a_only", "b_only")


def _groups(pf: PairFiles) -> tuple[dict[str, list[AlignedFile]], int]:
    """The pair's .ko by status and the count of the same ones. Read from the alignment alone:
    nothing is parsed. renamed (equal sha256 under another path) and undetermined (a side recorded
    no sha256) are lists of their own — never folded into content_differs or a_only."""
    groups: dict[str, list[AlignedFile]] = {k: [] for k in _LIST_KEYS}
    same = 0
    for af in aligned_ko(pf):
        if af.status == "same":
            same += 1
        else:
            groups[af.status].append(af)
    return groups, same


def ko_counts(pf: PairFiles) -> dict[str, Any]:
    """The .ko block of the first page: how many modules fall under each status, never their lists
    (they are read with ko_offset) — no module is parsed for it."""
    groups, same = _groups(pf)
    return {
        "scan_scope": "excluded",
        "same_count": same,
        **{f"{k}_count": len(v) for k, v in groups.items()},
        "lists_paged_by": "ko_offset",
        "note": KO_NOTE,
    }


def _item(pf: PairFiles, key: str, af: AlignedFile) -> dict[str, Any]:
    if key == "content_differs":
        return _content_entry(pf, af)
    if key == "a_only":
        return {"path": af.path_a, "sha": af.sha_a, "paired_by": af.paired_by}
    if key == "b_only":
        return {"path": af.path_b, "sha": af.sha_b, "paired_by": af.paired_by}
    return {"path_a": af.path_a, "path_b": af.path_b, "sha_a": af.sha_a, "sha_b": af.sha_b}


def paged_lists(
    lists: dict[str, list[Any]],
    offset: int,
    limit: int,
    budget: int,
    render: Callable[[str, Any], dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Every list cut at the same item: items ``offset`` .. ``offset + k`` of each, ``k`` at most
    ``limit`` and the most whose JSON encoding stays within ``budget`` bytes (always one).
    ``render(key, item)`` makes one list item; an item is rendered only when its page is read."""
    out: dict[str, list[dict[str, Any]]] = {key: [] for key in lists}
    used = 0
    k = 0
    longest = max((len(v) for v in lists.values()), default=0)
    while offset + k < longest and k < limit:
        row = {key: render(key, v[offset + k]) for key, v in lists.items() if offset + k < len(v)}
        size = sum(len(json.dumps(x)) + 2 for x in row.values())
        if k > 0 and used + size > budget:
            break
        for key, x in row.items():
            out[key].append(x)
        used += size
        k += 1
    return out, k
