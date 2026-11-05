# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""What one extraction JVM is started with: its command line, its environment, and the patched copy
of an ELF the decompiler could not import as it is.

Everything here decides what the extraction reads, so this module is part of the extraction pass's
fingerprint (``ghidra_runner._PIPELINE_PY_MODULES``): change the arguments, the environment or the
patch, and every binary is extracted again. The scheduling around it (pools, retries, budgets) is
not, and stays in ``ghidra_runner``.

★ The environment is a WHITELIST. The JVM used to inherit the whole parent environment, so a
variable nobody set on purpose (``_JAVA_OPTIONS`` overriding the heap, a leftover
``TMAP_EXTRA_SINKS`` adding sinks, an ``XDG_*`` moving Ghidra's settings) could change an
extraction while its fingerprint said nothing had changed. Now the JVM sees the keys this module
sets (``JVM_SET_KEYS``) and the few system variables it needs to start (``JVM_INHERITED_KEYS``),
and nothing else.

★ The time budgets are deliberately NOT in the fingerprint. The analysis timeout, the decompile
retry budget and its deadline decide WHICH functions time out, never what a finished one holds:
every function records its own outcome (``decompile_status``: a timeout reads as a timeout, never as
an empty function), so another budget can only leave more or fewer of them unfinished, which is
recorded, not a different fact.
"""

from __future__ import annotations

import shutil
import struct
import tempfile
from collections.abc import Mapping
from pathlib import Path

PROMOTE_SCRIPT = "PromoteUndefined.java"
EXTRACT_SCRIPT = "ExportFunctions.java"

# The environment keys the extraction JVM is started with, set by build_env from the arguments it is
# given. The extractor reads these (and only these) from its environment.
JVM_SET_KEYS: frozenset[str] = frozenset(
    {
        "OUTPUT_DIR",
        "SHA8",
        "PASS_VERSION",
        "TMAP_STUB_NAMES",
        "TMAP_DECOMPILE_RETRY_BUDGET_S",
        "TMAP_DECOMPILE_DEADLINE_MS",
        "TMAP_DECOMPILE_PAYLOAD_MB",
        "JAVA_TOOL_OPTIONS",
    }
)
# What is passed through from the parent, because the launcher needs it to start at all: where to
# find programs and the JDK, and the locale (text encoding).
JVM_INHERITED_KEYS: frozenset[str] = frozenset({"PATH", "JAVA_HOME", "LANG", "LC_ALL", "LC_CTYPE"})


def build_cmd(
    headless: Path,
    binary: Path,
    arch: str,
    proj_dir: Path,
    log_path: Path,
    script_path: str,
    timeout_s: int,
    after: list[str] | None = None,
) -> list[str]:
    """The analyzeHeadless command line of one extraction. ``after`` are further post-script
    arguments the caller runs once the extraction is done (the export, which is fingerprinted on
    its own); ``script_path`` is every directory those scripts are found in, ';'-separated."""
    return [
        str(headless),
        str(proj_dir),
        "Proj",
        "-processor",
        arch,
        "-postScript",
        PROMOTE_SCRIPT,
        "-postScript",
        EXTRACT_SCRIPT,
        *(after or []),
        "-scriptPath",
        script_path,
        "-deleteProject",
        "-log",
        str(log_path),
        "-analysisTimeoutPerFile",
        str(timeout_s),
        "-import",
        str(binary),
    ]


def build_env(
    parent: Mapping[str, str],
    *,
    output_dir: Path,
    sha8: str,
    pass_version: str,
    heap_mb: int,
    xms_mb: int,
    user_home: Path,
    stub_table: Path | None,
    retry_budget_s: int,
    deadline_ms: int,
    payload_mb: int | None,
) -> dict[str, str]:
    """The extraction JVM's whole environment: the system variables it needs from ``parent`` and
    the keys set here — nothing else of ``parent`` (see the module docstring). ``stub_table`` and
    ``payload_mb`` are left out when None: no table handed in, the default output limit."""
    env = {k: v for k, v in parent.items() if k in JVM_INHERITED_KEYS}
    env.update(
        {
            "OUTPUT_DIR": str(output_dir),
            "SHA8": sha8,
            # echoed back into the JSON by the extractor, so the output proves which pass wrote it
            "PASS_VERSION": pass_version,
            # every Ghidra setting stays inside this temporary user home
            "JAVA_TOOL_OPTIONS": f"-Xmx{heap_mb}m -Xms{xms_mb}m -Duser.home={user_home}",
            "TMAP_DECOMPILE_RETRY_BUDGET_S": str(retry_budget_s),
            "TMAP_DECOMPILE_DEADLINE_MS": str(deadline_ms),
        }
    )
    if stub_table is not None:
        env["TMAP_STUB_NAMES"] = str(stub_table)
    if payload_mb is not None:
        env["TMAP_DECOMPILE_PAYLOAD_MB"] = str(payload_mb)
    return env


def _patch_elf_for_ghidra(src: Path) -> tuple[Path, Path] | None:
    """Create a patched ELF copy with sections that trigger Ghidra 11.1.2's
    StringIndexOutOfBoundsException neutralised (sh_type → SHT_NULL).

    Affected: SHT_NOTE sections whose name is "GNU" (3-4 bytes), and
    SHT_ARM_ATTRIBUTES sections.  Both are safe to nullify for decompilation.

    Returns (patched_file, tmpdir) where patched_file has the SAME NAME as src
    so Ghidra's currentProgram.getName() matches what the caller expects.
    Caller must shutil.rmtree(tmpdir) after use.
    Returns None if no patch is needed or if patching fails.
    """
    try:
        data = bytearray(src.read_bytes())
    except OSError:
        return None

    if data[:4] != b"\x7fELF" or len(data) < 64:
        return None

    ei_class = data[4]
    fmt = "<" if data[5] == 1 else ">"

    if ei_class == 1:  # ELF32
        e_shoff: int = struct.unpack_from(fmt + "I", data, 32)[0]
        e_shentsize: int = struct.unpack_from(fmt + "H", data, 46)[0]
        e_shnum: int = struct.unpack_from(fmt + "H", data, 48)[0]
        sh_off_off, sh_sz_off, sh_off_fmt = 16, 20, fmt + "I"
        min_entsize = 40
    elif ei_class == 2:  # ELF64
        e_shoff = struct.unpack_from(fmt + "Q", data, 40)[0]
        e_shentsize = struct.unpack_from(fmt + "H", data, 58)[0]
        e_shnum = struct.unpack_from(fmt + "H", data, 60)[0]
        sh_off_off, sh_sz_off, sh_off_fmt = 24, 32, fmt + "Q"
        min_entsize = 64
    else:
        return None

    if e_shoff == 0 or e_shentsize < min_entsize:
        return None

    sht_note = 7
    sht_arm_attributes = 0x70000003

    patched = False
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + e_shentsize > len(data):
            break

        sh_type: int = struct.unpack_from(fmt + "I", data, off + 4)[0]
        neutralise = False

        if sh_type == sht_arm_attributes:
            neutralise = True
        elif sh_type == sht_note:
            sec_off: int = struct.unpack_from(sh_off_fmt, data, off + sh_off_off)[0]
            sec_size: int = struct.unpack_from(sh_off_fmt, data, off + sh_sz_off)[0]
            if sec_size >= 12 and 0 < sec_off <= len(data) - sec_size:
                namesz: int = struct.unpack_from(fmt + "I", data, sec_off)[0]
                if namesz in (3, 4) and data[sec_off + 12 : sec_off + 15] == b"GNU":
                    neutralise = True

        if neutralise:
            struct.pack_into(fmt + "I", data, off + 4, 0)
            struct.pack_into(sh_off_fmt, data, off + sh_off_off, 0)
            struct.pack_into(sh_off_fmt, data, off + sh_sz_off, 0)
            patched = True

    if not patched:
        return None

    tmpdir = Path(tempfile.mkdtemp(prefix="tm_elfpatch_"))
    try:
        patched_file = tmpdir / src.name  # same name → Ghidra uses correct program name
        patched_file.write_bytes(bytes(data))
        return patched_file, tmpdir
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None
