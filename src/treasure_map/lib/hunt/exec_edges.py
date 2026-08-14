# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Cross-binary launch edges: "binary A's code calls exec with an argument naming B".

The call graph inside one binary is well covered; the edge BETWEEN binaries is not. A router's web
daemon rarely does the interesting work itself — it shells out. Those callsites are already
described by the per-function sink argument provenance the extractor computes; this module reads
that description, works out which token names the launched program, and resolves the token against
the rootfs link inventory so ``/bin/sh -> busybox`` becomes a real edge rather than a dead token.

★ IRON LAW — this module ENUMERATES, it does not judge. An edge says a callsite exists, never that
it runs, never that an attacker reaches it. Nothing here may produce a 'blocked' state: the
reachability layer consuming these edges answers found/unknown only. A token that cannot be read is
reported unresolved; a token read but matched to nothing is reported unmatched WITH the plain facts
that separate damage from ambiguity from a genuine miss. Neither is ever quietly dropped.

The two sink families are disjoint and mean different things:

SHELL (``system`` / ``popen`` / ``doSystem``)
    The argument is a whole command line. The launched program is its first word; the image is
    always ``/bin/sh`` and is deliberately not listed as a second edge (it would swamp the table
    with a constant). The command text stays visible, so pipes and a wrapping ``sh -c`` are read
    out of it.
EXEC (``execl`` / ``execlp`` / ``execle`` / ``execv`` / ``execvp`` / ``execve``)
    The argument is the image path itself. ★ VARIADIC IRON LAW: argv is structurally invisible
    here — a variadic argument list, or an array the caller built elsewhere. arg0 is recorded and
    argv is NEVER reconstructed or guessed. When arg0 is a shell, that is recorded as shell_wrapped
    with ``inner_command_visible=0``: tmap can see that a shell was launched and must NOT pretend
    to know the command it was handed.

★ CALLSITE ATTRIBUTION IS AN OVER-APPROXIMATION, on purpose. A stack buffer reused by several
exec points has EVERY one of its writers read at EVERY one of those points — dropping a writer
would drop a real launch, so the widening is the safe direction. The consequence is that
``sink_addr`` means "some exec point in this function", not "the point that runs this token": in a
function that reuses one buffer, each callsite carries the whole buffer's command set (a real
firmware has one function with 102 callsites all carrying the same token set; about a quarter of
all callsites expand to several targets, and most resolved edges come from such callsites).
"Function A can run X" is TRUE; "this callsite runs X" is not guaranteed. Fragments of a command
assembled piecewise (``strcpy(buf, " > /tmp/out")``) are read as tokens of their own and land
unmatched with a bare token form; no heuristic tries to tell a whole command from a fragment,
because that is a semantic judgement and it would drop real launches whose program name is written
as a relative path. Read ``argv_template`` and judge.

★ MULTI-CANDIDATE TOKENS. A bare token can name several things: two directories holding different
scripts of the same name, or a name several symlinks claim. The resolution state still says what
KIND of thing was found, but ``target_binary`` is left empty rather than picking one. The
candidates are not lost — looking the token's basename up in the script inventory (shell scripts)
or the link inventory recovers them — so this is a choice with an exit, not an omission.

★ SCOPE BOUNDARY — the provenance this reads is per-function and per-DIRECT-callee. When the real
sink sits behind a thin forwarding wrapper (``caller f -> W -> system``), f's provenance does not
contain that ``system`` at all — it belongs to W. This module then sees only W's own
``system(param)``, which reads as unresolved, and the command f actually built is invisible to it.
That gap is REPORTED (the scan status names it), never papered over. Closing it needs a shared
upstream capability — following a thin wrapper and carrying the wrapped sink's forwarded argument
provenance — which serves several dimensions at once and does not belong to this enumerator. When
that capability lands, this module should consume its wrapped callsites: one more edge at f, routed
through W, with the target read from the wrapped sink's own argument.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any

from treasure_map.lib.atlas.models import ExecEdgeRow
from treasure_map.lib.diff.loader import FuncRow
from treasure_map.lib.fmt_spec import conversions

# The command-string family: the argument is a shell command line, not an image path.
SHELL_SINKS = frozenset({"system", "popen", "doSystem"})
# The image-path family: the argument is the program to run.
EXEC_SINKS = frozenset({"execl", "execlp", "execle", "execv", "execvp", "execve"})

# Interpreters recognized as "a shell was launched". Deliberately a small, literal set: guessing
# from a name would be a semantic claim about what the launched program does.
_SHELL_NAMES = frozenset({"sh", "ash", "bash", "dash", "ksh", "zsh"})

_SELF_EXE = "/proc/self/exe"

# Placeholder markers. A token carrying either is a TEMPLATE, not a name — it must never be
# matched against the inventory as if it were one.
_PLACEHOLDERS = ("%", "$")

# Recursion cap when walking a provenance record's nested sources.
_MAX_PROV_DEPTH = 4

TOKEN_CLEAN = "clean_literal"
TOKEN_NONE = "none"

RESOLVED_DIRECT = "resolved_direct"
RESOLVED_SYMLINK = "resolved_symlink"
RESOLVED_SCRIPT = "resolved_script"
SELF_EXEC = "self_exec"
UNRESOLVED = "unresolved"
UNMATCHED = "unmatched"

# The six states, for the totality check the tests assert against.
TARGET_RESOLUTIONS = frozenset(
    {RESOLVED_DIRECT, RESOLVED_SYMLINK, RESOLVED_SCRIPT, SELF_EXEC, UNRESOLVED, UNMATCHED}
)

LAYER_SHELL = "shell_command"
LAYER_EXEC = "exec_image"

# What the scan status tells a reader an empty or partial result does NOT cover.
UNSUPPORTED_NOTE = (
    "posix_spawn is not extracted (absent from the provenance sink lexicon); a runtime applet "
    "chain (busybox deciding by argv[0]) is not followed; for the exec* family only arg0 is "
    "recorded and argv is structurally invisible; a link the extraction tool damaged is marked "
    "corrupt and never repaired; a link whose target is not a known binary is marked "
    "target_unresolved rather than guessed; and a call sitting behind a thin command wrapper is "
    "INVISIBLE here — the caller's provenance does not contain the wrapped sink, so only the "
    "wrapper's own forwarded argument is seen (as unresolved). Closing that needs the shared "
    "wrapper-traversal capability; until then this table under-counts such callers. "
    "Attribution to a CALLSITE is an over-approximation: a stack buffer reused by several exec "
    "points has all of its writers read at each of them (dropping one would drop a real launch), "
    "so sink_addr means 'some exec point in this function', not 'the point that runs this token' "
    "— 'this function can run X' is true, 'this callsite runs X' is not guaranteed, and recovering "
    "a program name from a command template widens which edges this covers without changing the "
    "proportion. A token naming several candidates (two scripts sharing a basename, a link with "
    "several targets) keeps its resolution state but no target_binary — look the basename up in "
    "the script or link inventory to see the candidates."
)


# ── symlink index ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SymlinkIndex:
    """Both lookup directions over the rootfs link inventory, plus the damaged ones.

    ``by_path`` answers an absolute token (``/bin/sh``) and is unique by construction — one path
    holds one link. ``by_name`` answers a bare token (``sh``) and may hit several links in
    different directories, which is where ambiguity comes from. The two ``corrupt_*`` sets hold
    the links whose target the extraction tool destroyed; they are kept SEPARATE so a damaged link
    is reported as damaged instead of silently reading as "no such link"."""

    by_path: dict[str, str] = field(default_factory=dict)
    by_name: dict[str, tuple[str, ...]] = field(default_factory=dict)
    corrupt_by_path: frozenset[str] = frozenset()
    corrupt_by_name: frozenset[str] = frozenset()


def build_symlink_index(
    rows: list[tuple[str | None, str | None, str | None, str | None]],
) -> SymlinkIndex:
    """Index ``(link_path, link_name, target_name, corrupt_reason)`` rows for token lookup.

    Link paths are stored relative to the firmware root but tokens are written the way the firmware
    sees them (``/bin/sh``), so the path key is given its leading slash back here — one place, so
    the two spellings can never drift apart at a call site."""
    by_path: dict[str, str] = {}
    by_name: dict[str, list[str]] = {}
    corrupt_paths: set[str] = set()
    corrupt_names: set[str] = set()
    for link_path, link_name, target_name, corrupt_reason in rows:
        if not link_name:
            continue
        abs_path = "/" + link_path.lstrip("/") if link_path else None
        if corrupt_reason:
            if abs_path:
                corrupt_paths.add(abs_path)
            corrupt_names.add(link_name)
            continue
        if not target_name:
            continue
        if abs_path:
            by_path[abs_path] = target_name
        bucket = by_name.setdefault(link_name, [])
        if target_name not in bucket:
            bucket.append(target_name)
    return SymlinkIndex(
        by_path=by_path,
        by_name={k: tuple(sorted(v)) for k, v in by_name.items()},
        corrupt_by_path=frozenset(corrupt_paths),
        corrupt_by_name=frozenset(corrupt_names),
    )


@dataclass(frozen=True)
class SymlinkMatch:
    """What the link inventory had to say about one token.

    At most one of the four flags is set. ``matched_targets`` names the link target(s) that were
    hit — for a resolution it is the answer, and for ``target_unresolved`` it is the honest
    "the link exists and points HERE, that target just is not a known binary"."""

    via_symlink: bool = False
    ambiguous: bool = False
    corrupt: bool = False
    target_unresolved: bool = False
    matched_targets: tuple[str, ...] = ()


def resolve_symlink(token: str, index: SymlinkIndex, bin_names: frozenset[str]) -> SymlinkMatch:
    """Resolve ``token`` through the rootfs link inventory.

    An absolute token matches by full path, which is unique. A bare token matches by name, which
    may hit several links — and ambiguity is judged on the VERIFIABLE targets only:

      exactly one target is a known binary  -> resolved. Marking this ambiguous would throw away a
                                               real edge for the sake of targets that do not exist.
      several targets are known binaries    -> genuinely undecided. NOT guessed.
      no target is a known binary           -> ``target_unresolved``: the link is there, it points
                                               at ``matched_targets``, and that target simply is
                                               not in the binary inventory.

    ★ That last branch is DEFAULT-DENY and it is the load-bearing one. Any link hit that does not
    land on an inventory member — target not extracted, target is a script, target is another
    link, or some damage shape nobody has met yet — falls into it and degrades VISIBLY. It is
    deliberately not folded into the script state, which would corrupt that state's meaning ("the
    token itself is a .sh")."""
    if token.startswith("/"):
        if token in index.corrupt_by_path:
            return SymlinkMatch(corrupt=True)
        target = index.by_path.get(token)
        if target is None:
            return SymlinkMatch()
        if target in bin_names:
            return SymlinkMatch(via_symlink=True, matched_targets=(target,))
        return SymlinkMatch(target_unresolved=True, matched_targets=(target,))

    base = posixpath.basename(token)
    if base in index.corrupt_by_name and base not in index.by_name:
        return SymlinkMatch(corrupt=True)
    hits = index.by_name.get(base)
    if not hits:
        return SymlinkMatch()
    valid = tuple(sorted(t for t in hits if t in bin_names))
    if len(valid) == 1:
        return SymlinkMatch(via_symlink=True, matched_targets=valid)
    if len(valid) > 1:
        return SymlinkMatch(ambiguous=True, matched_targets=valid)
    return SymlinkMatch(target_unresolved=True, matched_targets=tuple(sorted(hits)))


# ── the six-state classification ──────────────────────────────────────────────────────


def classify_target_resolution(
    token: str,
    token_kind: str,
    *,
    in_binaries: bool,
    match: SymlinkMatch,
    in_non_binary: bool,
) -> str:
    """Total, mutually exclusive classification of one target token into the six states.

    Every input lands in exactly one state — there is no fall-through and no None. ``unmatched`` is
    the honest catch-all: ambiguity, damage, an unverifiable link target, a genuinely missing
    program, and a shell built-in all arrive there, and the row's separate fact columns are what
    let a reader tell them apart. tmap does not make that call."""
    if token == _SELF_EXE:
        return SELF_EXEC
    if token_kind != TOKEN_CLEAN:
        return UNRESOLVED
    if in_binaries:
        return RESOLVED_DIRECT
    if match.via_symlink:
        return RESOLVED_SYMLINK
    if in_non_binary:
        # ★ Membership of the script inventory is the WHOLE test. It used to also demand a `.sh`
        # suffix, which reads backwards on a real rootfs: a script invoked as a program is exactly
        # the one without a suffix (an init.d entry, an sbin helper), while `.sh` tends to mark the
        # library scripts other scripts source. That extra gate pushed known scripts into
        # `unmatched` — reporting "I do not recognize this" about a file the inventory holds. The
        # inventory is populated from the extractor's own file classification and the query behind
        # it selects shell scripts only, so no other kind of file can arrive here; tmap adds no
        # second-guessing heuristic of its own on top of that classification.
        return RESOLVED_SCRIPT
    return UNMATCHED


def enters_entry_reach(target_resolution: str) -> bool:
    """May this edge be offered to the reachability layer as an entry site?

    Only a target that resolved to an actual binary in this run's inventory: those two states name
    a program the reader can go and read. A script target names a file, not a binary, and every
    remaining state names something tmap could not pin down — offering either would put a site on a
    candidate on the strength of a token that matched nothing.

    Total over every string: anything unrecognized answers False (an unknown state must never
    silently grant an entry site)."""
    return target_resolution in (RESOLVED_DIRECT, RESOLVED_SYMLINK)


def token_form(token: str) -> str:
    """How the token was written: an absolute path, a path relative to some cwd, or a bare name.

    A reader uses this to separate the two open cases inside ``unmatched``: an absolute token that
    matched nothing is a suspected extraction gap, while a bare token that matched nothing may
    simply be a shell built-in or a PATH tool. tmap supplies the shape; the reader concludes."""
    if token.startswith("/"):
        return "absolute"
    return "relative" if "/" in token else "bare"


# ── reading the target token out of the sink argument provenance ──────────────────────


def _arg_values(prov: Any, depth: int = 0) -> list[str | None]:
    """Every string the sink's key argument may hold, per the extractor's def-use record.

    A readable constant yields its text. A stack buffer yields the format string of EACH of its
    writers — ★ ALL writers, not only the dominating ones. That differs on purpose from the
    controllability layer, which filters to dominating writers so it never over-asserts a verdict:
    here the question is "which programs can this callsite launch", and dropping a writer on a
    conditional branch would delete a real launch edge. Enumeration widens where a verdict
    narrows. A phi merge recurses into every origin. Anything else yields None — the honest "no
    readable token", which becomes ``unresolved``, never a silent skip."""
    if depth > _MAX_PROV_DEPTH or not isinstance(prov, dict):
        return [None]
    kind = prov.get("kind")
    if kind == "constant":
        # A constant that no string reads out of ("ambiguous_0x") is a confirmed constant whose
        # text is unknown — it is NOT a token, and must not be matched as one.
        if prov.get("value_kind") == "literal_string" and isinstance(prov.get("value"), str):
            return [prov["value"]]
        return [None]
    if kind == "stack_buf":
        out: list[str | None] = []
        for writer in prov.get("writers") or []:
            if not isinstance(writer, dict):
                continue
            fmt = writer.get("fmt")
            if isinstance(fmt, str):
                out.append(_substitute_constant_args(fmt, writer.get("varargs")))
            elif isinstance(writer.get("src_source"), dict):
                out.extend(_arg_values(writer["src_source"], depth + 1))
        return out or [None]
    if kind == "multiple":
        out = []
        for source in prov.get("sources") or []:
            out.extend(_arg_values(source, depth + 1))
        return out or [None]
    return [None]


def _substitute_constant_args(fmt: str, varargs: Any) -> str:
    """Fill a writer's format string with the arguments that are compile-time constants.

    A command is very often built as ``snprintf(buf, "%s '%s'", "/usr/sbin/tool -j", user)``. Read
    as a template, the first word is ``%s`` — the program name is invisible and the edge resolves
    to nothing, even though the name is sitting right there as a constant argument. Substituting
    the constants back recovers it.

    ★ Only CONSTANT arguments are substituted. A runtime one stays as its conversion, so the
    template still shows what is unknown and ``argv_visibility`` still reports a placeholder — the
    first word becomes readable without the rest being claimed. Substituting a runtime argument
    would fabricate a target; substituting at the wrong offset would name the wrong one, which is
    why the conversion-to-argument mapping comes from the shared scanner rather than a local count
    of ``%`` characters.

    Conversions are replaced back-to-front so the earlier ones keep their recorded offsets."""
    args = varargs if isinstance(varargs, list) else []
    if not args:
        return fmt
    out = fmt
    for conv in reversed(conversions(fmt)):
        if conv.char != "s" or conv.stars:  # a %d is a number, not a name; a * shifts the mapping
            continue
        if conv.arg_index >= len(args):
            continue  # fewer arguments than the format consumes — nothing to put here
        entry = args[conv.arg_index]
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        # Only a constant the extractor could READ OUT as text carries this mark. That covers both
        # refusals at once: a runtime value has no mark (leave the conversion, honestly unknown),
        # and a constant whose text could not be read has a different one (a confirmed constant
        # whose bytes are unknown is not a name).
        if not isinstance(source, dict) or source.get("value_kind") != "literal_string":
            continue
        value = source.get("value")
        if isinstance(value, str):
            out = out[: conv.start] + value + out[conv.end :]
    return out


def _dedup(values: list[str | None]) -> list[str | None]:
    """Order-preserving de-duplication (one callsite must not emit the same token twice)."""
    seen: set[str | None] = set()
    out: list[str | None] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


# ── shell command-line parsing ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ShellCommand:
    """A shell command line reduced to the program it starts with, plus the shape it was in."""

    first_word: str
    piped: bool
    shell_wrapped: bool
    inner: str


def _strip_quotes(text: str) -> str:
    for quote in ('"', "'"):
        if len(text) >= 2 and text.startswith(quote) and text.endswith(quote):
            return text[1:-1]
    return text.strip("\"'")


def _drop_leading_assignments(text: str) -> str:
    """Drop ``VAR=value`` prefixes: they configure the command, they are not the command."""
    while True:
        words = text.split(maxsplit=1)
        if not words:
            return text
        head = words[0]
        eq = head.find("=")
        if eq <= 0 or not head[:eq].replace("_", "").isalnum():
            return text
        text = words[1] if len(words) > 1 else ""


def _has_pipe(text: str) -> bool:
    """A real pipeline, not a boolean OR (``a || b`` chains two commands, it does not pipe)."""
    return "|" in text.replace("||", "\x00\x00")


def _first_segment(text: str) -> str:
    """Everything up to the first real pipe — where the launched program's name lives."""
    masked = text.replace("||", "\x00\x00")
    idx = masked.find("|")
    return text if idx < 0 else text[:idx]


def parse_shell_command(command: str) -> ShellCommand:
    """Reduce a shell command line to the program it launches.

    Peeled in the order a shell itself would read them: a wrapping subshell ``(``, then ``VAR=``
    assignments, then an explicit ``sh -c`` (whose inner command is what actually runs, so the peel
    repeats on it), and finally the pipeline — the first stage is the launched program.

    ★ Only pipelines split the command. A ``;`` or ``&&`` sequence names several programs, and this
    reports the first one; the others are a known gap rather than a wrong answer."""
    text = command.strip()
    shell_wrapped = False
    for _ in range(3):  # one -c unwrap, plus the prefixes that may sit inside it
        while text.startswith("("):
            text = text[1:].lstrip()
        text = _drop_leading_assignments(text).lstrip()
        words = text.split()
        if len(words) >= 3 and posixpath.basename(words[0]) in _SHELL_NAMES and words[1] == "-c":
            shell_wrapped = True
            text = text[len(words[0]) :].lstrip()  # drop the interpreter
            text = text[2:].lstrip()  # drop the -c
            text = _strip_quotes(text.strip())
            continue
        break
    piped = _has_pipe(text)
    segment = _first_segment(text).split()
    return ShellCommand(
        first_word=_strip_quotes(segment[0]) if segment else "",
        piped=piped,
        shell_wrapped=shell_wrapped,
        inner=text,
    )


def _token_kind(token: str) -> str:
    """A token is usable only if it is a NAME. An empty token, or one still carrying a format
    placeholder, is a template whose real value is unknown — reported as no token at all."""
    if not token or any(marker in token for marker in _PLACEHOLDERS):
        return TOKEN_NONE
    return TOKEN_CLEAN


# ── edge assembly ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _EdgeFacts:
    """The family-dependent half of an edge, before the target token is resolved."""

    target_layer: str
    token: str
    token_kind: str
    shell_wrapped: int
    piped: int
    inner_command_visible: int
    argv_visibility: str
    argv_template: str | None


def _shell_facts(value: str | None) -> _EdgeFacts:
    parsed = parse_shell_command(value or "")
    has_placeholder = any(marker in (value or "") for marker in _PLACEHOLDERS)
    return _EdgeFacts(
        target_layer=LAYER_SHELL,
        token=parsed.first_word,
        token_kind=TOKEN_NONE if value is None else _token_kind(parsed.first_word),
        shell_wrapped=int(parsed.shell_wrapped),
        piped=int(parsed.piped),
        # The shell family hands the sink a command STRING, so whatever the shell will run is
        # right there in front of us — unlike the exec family, where it is a separate argument.
        inner_command_visible=1,
        argv_visibility="known_with_placeholder" if has_placeholder else "known",
        argv_template=value,
    )


def _exec_facts(value: str | None) -> _EdgeFacts:
    token = (value or "").strip()
    return _EdgeFacts(
        target_layer=LAYER_EXEC,
        token=token,
        token_kind=TOKEN_NONE if value is None else _token_kind(token),
        # arg0 being a shell means a shell was launched. What it was told to run rides in argv,
        # which is structurally invisible here — so this is recorded and NOT read into.
        shell_wrapped=int(posixpath.basename(token) in _SHELL_NAMES),
        piped=0,
        inner_command_visible=0,
        # ★ VARIADIC IRON LAW: argv is never reconstructed for this family.
        argv_visibility="structurally_invisible",
        argv_template=None,
    )


@dataclass(frozen=True)
class ExecEdgeInventory:
    """Everything the token resolution is matched against, gathered once per run.

    ``scripts`` maps a script's basename to its path(s) under the firmware root. Paths, not the
    token, because the token may be bare: a third of resolved script edges name their target with
    no directory at all, so recording the token would fill the target column with two different
    kinds of key. The path is already known at match time — it is what the inventory holds."""

    symlinks: SymlinkIndex
    bin_names: frozenset[str]
    scripts: dict[str, tuple[str, ...]] = field(default_factory=dict)


def build_exec_edges(
    funcs: list[FuncRow],
    sink_prov_by_func: dict[int, list[dict[str, Any]]],
    inventory: ExecEdgeInventory,
    source_run_id: str,
) -> list[ExecEdgeRow]:
    """Every cross-binary launch edge this run's provenance describes.

    Identical rows are folded on ``(binary, function, sink address, token)`` and counted in
    ``occurrences`` — one callsite reached by several paths is one edge, not several. Rows come out
    in a deterministic order so a re-hunt of unchanged input produces an unchanged table."""
    edges: dict[tuple[str | None, str | None, str | None, str], ExecEdgeRow] = {}
    for func in funcs:
        for record in sink_prov_by_func.get(func.func_id, ()):
            if not isinstance(record, dict):
                continue
            api = record.get("sink")
            if api in SHELL_SINKS:
                facts_of = _shell_facts
            elif api in EXEC_SINKS:
                facts_of = _exec_facts
            else:
                continue  # a format-string sink: it launches nothing
            sink_addr = record.get("sink_addr")
            for value in _dedup(_arg_values(record.get("provenance"))):
                facts = facts_of(value)
                row = _build_row(func, api, sink_addr, facts, inventory, source_run_id)
                key = (func.binary_name, func.name, row.sink_addr, row.target_token or "")
                existing = edges.get(key)
                if existing is None:
                    edges[key] = row
                else:
                    edges[key] = replace_occurrences(existing, existing.occurrences + 1)
    return [edges[k] for k in sorted(edges, key=lambda k: tuple(str(p) for p in k))]


def replace_occurrences(row: ExecEdgeRow, occurrences: int) -> ExecEdgeRow:
    """A copy of ``row`` with a new occurrence count (the row type is frozen)."""
    return ExecEdgeRow(**{**row.__dict__, "occurrences": occurrences})


def _build_row(
    func: FuncRow,
    api: str | None,
    sink_addr: str | None,
    facts: _EdgeFacts,
    inventory: ExecEdgeInventory,
    source_run_id: str,
) -> ExecEdgeRow:
    """Resolve one token and assemble its row, honesty flags included."""
    token = facts.token
    base = posixpath.basename(token)
    readable = facts.token_kind == TOKEN_CLEAN and token != _SELF_EXE
    match = (
        resolve_symlink(token, inventory.symlinks, inventory.bin_names)
        if readable
        else (SymlinkMatch())
    )
    script_paths = inventory.scripts.get(base, ())
    resolution = classify_target_resolution(
        token,
        facts.token_kind,
        in_binaries=readable and base in inventory.bin_names,
        match=match,
        in_non_binary=bool(script_paths),
    )
    target_binary: str | None = None
    if resolution == RESOLVED_DIRECT:
        target_binary = base
    elif resolution == RESOLVED_SYMLINK:
        target_binary = match.matched_targets[0] if match.matched_targets else None
    elif resolution == RESOLVED_SCRIPT and len(script_paths) == 1:
        # One path for this name -> that path IS the target, and the edge becomes answerable.
        # SEVERAL paths (genuinely different scripts sharing a basename) -> left NULL: picking one
        # would be a guess, and the candidates are recoverable by looking the basename up in the
        # script inventory.
        target_binary = script_paths[0]
    # The three symlink facts describe an UNMATCHED token. On a resolved token they would be noise
    # about a road not taken (a link named like the target that the direct match already beat).
    unmatched = resolution == UNMATCHED
    return ExecEdgeRow(
        source_run_id=source_run_id,
        launcher_binary=func.binary_name,
        launcher_function=func.name,
        launcher_addr=func.address,
        exec_api=api,
        sink_addr=sink_addr,
        target_layer=facts.target_layer,
        shell_wrapped=facts.shell_wrapped,
        piped=facts.piped,
        inner_command_visible=facts.inner_command_visible,
        argv_visibility=facts.argv_visibility,
        argv_template=facts.argv_template,
        argv_provenance=facts.token_kind,
        target_token=token or None,
        target_resolution=resolution,
        token_form=token_form(token) if token else None,
        symlink_ambiguous=int(unmatched and match.ambiguous),
        symlink_corrupt=int(unmatched and match.corrupt),
        symlink_target_unresolved=int(unmatched and match.target_unresolved),
        target_binary=target_binary,
    )


def exec_entry_sites(rows: list[ExecEdgeRow]) -> dict[str, list[dict[str, Any]]]:
    """Group the entry-eligible edges by the binary they launch.

    ★ Only edges whose target resolved to a real binary are offered, and the site records the
    launcher, not a verdict. The reachability layer turns an offered site into ``found``; with no
    site it reports ``unknown``. Neither path can produce 'blocked' — an edge is a lead."""
    sites: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if not enters_entry_reach(row.target_resolution) or not row.target_binary:
            continue
        sites.setdefault(row.target_binary, []).append(
            {
                "kind": "exec_edge",
                "launcher_binary": row.launcher_binary,
                "launcher_function": row.launcher_function,
                "exec_api": row.exec_api,
                "target_token": row.target_token,
                "target_layer": row.target_layer,
                "arg_source": row.argv_visibility,
            }
        )
    return sites
