# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""The extractor name registry (analyze/ghidra/extractor_names.tsv) and its seams.

One file now holds every callee-name list the Ghidra extraction pass recognises; the Java pass and
the Python read side both parse it. These tests pin three things:

  * the MIGRATION was faithful — every name and position the extractor hard-coded before is in the
    registry unchanged, and the only additions are the ones deliberately made;
  * the two PARSERS agree — same header, same roles, same rejections — so a file one accepts the
    other accepts;
  * each read-side list is in step with the registry role it mirrors, with every intentional
    difference named in an allowlist that carries its reason (and the allowlist is asserted EQUAL,
    so it cannot quietly grow).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from treasure_map.lib.hunt import facts
from treasure_map.lib.pattern import classes
from treasure_map.lib.pattern.extractor_names import (
    HEADER,
    NVRAM_OPS,
    REGISTRY,
    REGISTRY_PATH,
    ROLES,
    RegistryError,
    load_registry,
    parse_registry,
    validate_registry,
)
from treasure_map.lib.query.sink_impact import NVRAM_GETTERS
from treasure_map.lib.reachability import copy_size

_JAVA = REGISTRY_PATH.parent / "ExportFunctions.java"


def _java() -> str:
    return _JAVA.read_text(encoding="utf-8")


# ── the migration: what the extractor hard-coded before is in the registry, unchanged ─────────

# The lists exactly as ExportFunctions.java hard-coded them before the registry existed.
_OLD_SINK_KEYARG = {
    **dict.fromkeys(
        ["system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve", "doSystem"], 0
    ),
    **dict.fromkeys(["printf", "vprintf", "warn", "warnx", "vwarn", "vwarnx"], 0),
    **dict.fromkeys(
        ["fprintf", "vfprintf", "dprintf", "vdprintf", "syslog", "vsyslog", "err", "errx"], 1
    ),
    **dict.fromkeys(["verr", "verrx", "asprintf", "vasprintf"], 1),
}
_OLD_WRITERS = frozenset(
    {
        "snprintf",
        "sprintf",
        "vsnprintf",
        "vsprintf",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "memcpy",
        "memmove",
        "stpcpy",
        "__sprintf_chk",
        "__snprintf_chk",
    }
)
_OLD_WRITER_FMTARG = {
    "sprintf": 1,
    "vsprintf": 1,
    "snprintf": 2,
    "vsnprintf": 2,
    "__sprintf_chk": 3,
    "__snprintf_chk": 4,
}
_OLD_TOKENIZERS = frozenset({"strtok", "strtok_r", "strsep", "sscanf"})
_OLD_FORWARD_CMD = frozenset({"system", "popen", "doSystem"})
# (op, key_idx, name_idx, val_idx) per accessor — the 33 hard-coded NvSpecs.
_OLD_NVRAM = {
    **dict.fromkeys(
        [
            "nvram_get",
            "nvram_get_int",
            "nvram_default_get",
            "nvram_contains_word",
            "nvram_get_hex",
            "nvram_get_r",
            "nvram_split_get",
            "wlcsm_nvram_get",
            "jffs_nvram_get",
            "nvram_is_empty",
            "nvram_valid_get_int",
            "nvram_get_bitflag",
            "nvram_get_double",
            "nvram_get_file",
            "internal_nvram_get_int",
        ],
        ("read", 0, -1, -1),
    ),
    **dict.fromkeys(
        [
            "nvram_set",
            "nvram_set_int",
            "nvram_set_hex",
            "nvram_restore_var",
            "wlcsm_nvram_set",
            "jffs_nvram_set",
        ],
        ("write", 0, -1, 1),
    ),
    **dict.fromkeys(["nvram_unset", "jffs_nvram_unset"], ("write", 0, -1, -1)),
    **dict.fromkeys(["nvram_pf_get", "nvram_pf_get_int", "nvram_pf_match"], ("read", 0, 1, -1)),
    **dict.fromkeys(["nvram_pf_set", "nvram_pf_set_int"], ("write", 0, 1, 2)),
    **dict.fromkeys(
        ["nvram_commit", "nvram_commit_x", "wlcsm_nvram_commit"], ("commit", -1, -1, -1)
    ),
    **dict.fromkeys(["nvram_getall", "jffs_nvram_getall"], ("getall", -1, -1, -1)),
}

# The names deliberately ADDED with the registry, nothing else.
_ADDED_WRITERS = frozenset(
    {
        "strlcpy",
        "strlcat",
        "mempcpy",
        "wmemcpy",
        "stpncpy",
        "__memcpy_chk",
        "__memmove_chk",
        "__mempcpy_chk",
        "__strcpy_chk",
        "__strncpy_chk",
        "__stpcpy_chk",
        "__stpncpy_chk",
        "__strcat_chk",
        "__strncat_chk",
        "__vsprintf_chk",
        "__vsnprintf_chk",
    }
)
_ADDED_WRITER_FMTARG = {"__vsprintf_chk": 3, "__vsnprintf_chk": 4}
_ADDED_NVRAM = {"nvram_bufget": ("read", 1, -1, -1), "nvram_bufset": ("write", 1, -1, 2)}
_PREDICATE_READS = frozenset(
    {"nvram_contains_word", "nvram_pf_match", "nvram_is_empty", "nvram_get_bitflag"}
)


def test_the_sink_lexicon_moved_unchanged() -> None:
    """Every provenance sink and its key position, exactly as hard-coded before.

    MUTATION (verified RED): change fprintf's key_idx to 0 in the TSV -> mismatch."""
    assert {**REGISTRY.sink_cmd, **REGISTRY.sink_fmt} == _OLD_SINK_KEYARG
    assert not set(REGISTRY.sink_cmd) & set(REGISTRY.sink_fmt)


def test_the_writer_lists_grew_by_exactly_the_intended_names() -> None:
    assert REGISTRY.writers == _OLD_WRITERS | _ADDED_WRITERS
    assert dict(REGISTRY.writer_fmt) == _OLD_WRITER_FMTARG | _ADDED_WRITER_FMTARG


def test_tokenizers_and_forward_cmd_moved_unchanged() -> None:
    """The tokenizer list has no Python consumer — the def-use pass reads it, nothing on the read
    side does — so this lock is its only seam."""
    assert REGISTRY.tokenizer == _OLD_TOKENIZERS
    assert REGISTRY.forward_cmd == _OLD_FORWARD_CMD


def test_every_nvram_accessor_moved_unchanged_and_two_were_added() -> None:
    """All 33 accessor specs unchanged; nvram_bufget / nvram_bufset added with the key in argument
    1 (their argument 0 is an index).

    MUTATION (verified RED): set nvram_bufget's key_idx to 0 -> mismatch."""
    got = {n: (s.op, s.key_idx, s.name_idx, s.val_idx) for n, s in REGISTRY.nvram.items()}
    assert got == _OLD_NVRAM | _ADDED_NVRAM


def test_value_returning_reads_exclude_the_predicates() -> None:
    reads = {n for n, s in REGISTRY.nvram.items() if s.op == "read"}
    assert REGISTRY.nvram_value_getters == reads - _PREDICATE_READS
    assert {n for n, s in REGISTRY.nvram.items() if s.returns_value is False} == _PREDICATE_READS
    assert all(s.returns_value is None for s in REGISTRY.nvram.values() if s.op != "read")


# ── the parser: what it accepts and what it refuses ───────────────────────────────────────────

_HDR = "\t".join(HEADER)
_MIN_ROWS = [
    "system\tsink_cmd\t\t0",
    "printf\tsink_fmt\t\t0",
    "strcpy\twriter",
    "sprintf\twriter_fmt\t\t\t\t\t1",
    "strtok\ttokenizer",
    "system\tforward_cmd",
    "nvram_get\tnvram\tread\t0\t-1\t-1\t\ttrue",
]


def _reg(*rows: str, header: str = _HDR) -> str:
    return "\n".join(["# comment", "", header, *rows]) + "\n"


def test_a_minimal_file_parses_with_trailing_empty_cells_omitted() -> None:
    r = parse_registry(_reg(*_MIN_ROWS))
    assert dict(r.sink_cmd) == {"system": 0}
    assert dict(r.writer_fmt) == {"sprintf": 1}
    assert r.writers == {"strcpy", "sprintf"}
    assert r.nvram_value_getters == {"nvram_get"}


@pytest.mark.parametrize(
    "rows,header,message",
    [
        (_MIN_ROWS, "name\trole", "header"),
        ([*_MIN_ROWS, "x\tsomething"], _HDR, "unknown role"),
        ([*_MIN_ROWS, "x\twriter\t\t\t\t\t\t\t\textra"], _HDR, "at most"),
        ([*_MIN_ROWS, "x\tsink_cmd\t\tnot_int"], _HDR, "integer"),
        ([*_MIN_ROWS, "strcpy\twriter"], _HDR, "duplicate"),
        ([*_MIN_ROWS, "x\tsink_cmd"], _HDR, "needs key_idx"),
        ([*_MIN_ROWS, "x\twriter_fmt"], _HDR, "needs fmt_idx"),
        ([*_MIN_ROWS, "x\tnvram\tfetch\t0"], _HDR, "op"),
        ([*_MIN_ROWS, "x\tnvram\tread\t0"], _HDR, "returns_value"),
        ([*_MIN_ROWS, "x\tnvram\twrite\t0\t-1\t1\t\ttrue"], _HDR, "reads only"),
        ([*_MIN_ROWS, "x\twriter\tread"], _HDR, "nvram rows only"),
        ([*_MIN_ROWS, "x\tnvram\tread\t0\t-1\t-1\t\tyes"], _HDR, "true/false"),
        ([*_MIN_ROWS, "9bad\twriter"], _HDR, "identifier"),
        (_MIN_ROWS[1:], _HDR, "no rows for role"),
    ],
)
def test_the_parser_refuses_anything_outside_the_format(
    rows: list[str], header: str, message: str
) -> None:
    """A malformed registry is never read leniently: the extractor would recognise less than it
    should and the result would look like "no sinks here"."""
    with pytest.raises(RegistryError, match=message):
        parse_registry(_reg(*rows, header=header))


def test_a_missing_file_is_a_registry_error(tmp_path: Path) -> None:
    with pytest.raises(RegistryError, match="cannot read"):
        load_registry(tmp_path / "absent.tsv")
    with pytest.raises(RegistryError):
        validate_registry(tmp_path / "absent.tsv")


def test_the_shipped_registry_validates() -> None:
    validate_registry()
    assert load_registry() == REGISTRY


# ── the Java parser mirrors this one ──────────────────────────────────────────────────────────


def _java_string_array(name: str) -> list[str]:
    m = re.search(rf"{name}\s*=\s*\{{([^}}]*)\}};", _java())
    assert m is not None, name
    return re.findall(r'"([^"]*)"', m.group(1))


def _java_string_set(name: str) -> set[str]:
    m = re.search(rf"{name}\s*=\s*new HashSet<>\(Arrays\.asList\(([^)]*)\)\);", _java())
    assert m is not None, name
    return set(re.findall(r'"([^"]*)"', m.group(1)))


def test_the_java_parser_uses_the_same_header_roles_and_ops() -> None:
    """The two parsers share their vocabulary; a role or column added to one and not the other
    would make a file valid for one reader and rejected by the other."""
    assert tuple(_java_string_array("REGISTRY_HEADER")) == HEADER
    assert _java_string_set("REGISTRY_ROLES") == ROLES
    assert _java_string_set("NVRAM_OPS") == NVRAM_OPS
    assert re.search(r'REGISTRY_FILE\s*=\s*"extractor_names\.tsv"', _java())
    assert REGISTRY_PATH.name == "extractor_names.tsv"


def test_the_java_pass_hard_codes_no_name_list_any_more() -> None:
    """Every list comes from the registry; a name literal re-added to a Java initialiser would be a
    second, silently diverging copy.

    MUTATION (verified RED): re-add `WRITERS.add("strcpy");` to the Java source."""
    src = _java()
    for pattern in (
        r'SINK_KEYARG\.put\("',
        r'WRITER_FMTARG\.put\("',
        r'(?:WRITERS|TOKENIZERS|FORWARD_CMD_SINKS|WRAPPER_BUILDERS)\.add\("',
        r'new NvSpec\("',
        r'Arrays\.asList\(\s*"(?:snprintf|strtok|system)"',
    ):
        assert re.search(pattern, src) is None, pattern


def test_the_registry_loads_before_any_lexicon_is_consulted() -> None:
    """run() loads the registry (and the stub table) before the extra-sink merge and before the
    wrapper registry is built — both read the lists it fills."""
    src = _java()
    run = src[src.index("public void run()") :]
    load = run.index("loadRegistry();")
    assert load < run.index("loadStubNames(")
    assert load < run.index('System.getenv("TMAP_EXTRA_SINKS")')
    assert load < run.index("buildCmdWrapperRegistry(decomp, fm);")


# ── each read-side list against the registry role it mirrors ──────────────────────────────────

# Writers that are never a copy/format candidate: they truncate to the destination size they are
# handed, so they are read only as writers of a stack buffer's fill.
_WRITER_ONLY: dict[str, str] = {
    "strlcpy": "size-bounded copy: writer only, never a copy candidate",
    "strlcat": "size-bounded append: writer only, never a format candidate",
}

# Getter names the read side recognises as nvram value sources that the extractor's accessor
# list does not carry (so it records no nvram op for them). Kept as preventive read-side names.
_READ_SIDE_ONLY_GETTERS: dict[str, str] = {
    "nvram_safe_get": "read-side-only getter name, not in the extractor's accessor list",
    "nvram_get_value": "read-side-only getter name, not in the extractor's accessor list",
    "nvram_get_state": "read-side-only getter name, not in the extractor's accessor list",
    "acosNvramConfig_get": "read-side-only getter name, not in the extractor's accessor list",
    "acosNvramConfig_read": "read-side-only getter name, not in the extractor's accessor list",
    "envram_get": "read-side-only getter name, not in the extractor's accessor list",
    "envram_safe_get": "read-side-only getter name, not in the extractor's accessor list",
}


def test_cmd_and_fmt_string_sinks_are_the_registry_sinks() -> None:
    """The read side's sink classes and format positions are the def-use pass's, exactly."""
    assert classes.CMD == frozenset(REGISTRY.sink_cmd)
    assert classes.FMT_STRING == frozenset(REGISTRY.sink_fmt)
    assert classes.FMT_STRING_ARG == dict(REGISTRY.sink_fmt)
    assert set(REGISTRY.sink_cmd.values()) == {0}


def test_copy_and_format_partition_the_registry_writers() -> None:
    """COPY and FORMAT split the extractor's writers between them, with only the named writer-only
    exceptions left out.

    MUTATION (verified RED): drop "__strcat_chk" from classes.FORMAT."""
    assert not classes.COPY & classes.FORMAT
    assert REGISTRY.writers - (classes.COPY | classes.FORMAT) == set(_WRITER_ONLY)
    assert (classes.COPY | classes.FORMAT) <= REGISTRY.writers
    assert classes.FORMAT_ARG == dict(REGISTRY.writer_fmt)
    assert set(classes.FORMAT_ARG) <= classes.FORMAT


def test_the_wrapper_test_builders_are_the_registry_writers() -> None:
    """The Python thin-wrapper test treats exactly the extractor's writers as builders — the set
    the extractor's own wrapper test derives its builders from — so the two judge a body alike."""
    assert facts._BUILDERS == REGISTRY.writers
    assert facts._FORWARD_CMD_SINKS == REGISTRY.forward_cmd
    assert REGISTRY.forward_cmd <= classes.CMD


def test_nvram_getters_against_the_registry() -> None:
    """Every read-side getter is either a value-returning registry read or a named read-side-only
    getter; none is a predicate read (which returns a yes/no, not the value)."""
    assert NVRAM_GETTERS - set(REGISTRY.nvram) == set(_READ_SIDE_ONLY_GETTERS)
    assert NVRAM_GETTERS & set(REGISTRY.nvram) <= REGISTRY.nvram_value_getters
    assert not NVRAM_GETTERS & _PREDICATE_READS


def test_the_size_tables_cover_every_copy_and_fortified_writer() -> None:
    """Length / cap / append / object-size positions exist for exactly the calls that have them."""
    assert classes.COPY == copy_size._SIZED_COPY | copy_size._UNSIZED_COPY
    assert set(copy_size._CAP_ARG) | set(copy_size._APPEND_ARG) <= classes.FORMAT
    fortified = {n for n in classes.COPY | classes.FORMAT if n.endswith("_chk")}
    assert set(copy_size._OBJSIZE_ARG) == fortified
