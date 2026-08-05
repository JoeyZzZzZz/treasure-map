# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
"""Shell tab-completion install — a standard step of ``tmap init`` (bash + zsh).

Completion rides along with init so a user who is setting tmap up anyway gets it with no extra
decision: there is no ``--no-completion`` flag, because a completion script is a pure, side-effect-
free convenience and a "skip it" toggle would only push a non-decision onto the user. "Installed by
default" and "honest about it" do not conflict: the script goes to a user-level autoload directory
(no side effects), and init + the doctor say exactly WHERE it went, WHETHER the shell will load it,
and — when it will not — the ONE line the user must add themselves.

Two hard rules (mirrors the rest of init):
  * NEVER touch the user's shell rc file without their explicit consent. Installing writes only to
    the shell's own autoload directory. When that is not enough to make completion load, init ASKS
    (a Y/N, interactive runs only) and appends a marked, idempotent block ONLY on a yes; a decline
    or a non-interactive run just PRINTS the one line for the user to add. What the rule protects
    is an rc changed behind the user's back — an explicit yes IS the user's decision, so consent
    satisfies it; silence never does.
  * NEVER silently claim success. If the script cannot be generated/written, or the shell will not
    pick it up, that is surfaced (init echo + a doctor check), not swallowed. An rc that cannot be
    appended to reports the failure and falls back to printing the line — never a false "added".

bash and zsh only — the vast majority of users. fish and others are added on demand, not pre-built.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import click
from click.shell_completion import get_completion_class

SUPPORTED_SHELLS = ("bash", "zsh")

# The fences around anything init appends to an rc. They exist so the block is RECOGNISABLE (the
# idempotence check is "is the start marker already there?") and REMOVABLE (a user can delete from
# one marker to the other and be exactly where they started). Never change them casually: an older
# marker left in an rc would stop matching and the block would be appended a second time.
_MARK_START = "# >>> tmap completion >>>"
_MARK_END = "# <<< tmap completion <<<"

# Click derives the runtime trigger var from the entry-point name (tmap -> _TMAP_COMPLETE); the
# generated script and the running CLI must agree on it, so it is named once here.
_COMPLETE_VAR = "_TMAP_COMPLETE"


@dataclass(frozen=True)
class CompletionInstall:
    """The outcome of installing (or refreshing) a completion script for one shell."""

    shell: str
    path: Path
    wrote: bool  # True if the file was created or updated this run (False = already current)
    active: bool  # our best-effort read of whether an interactive shell will load it
    activation_hint: str | None  # the exact one line the user must add when it is NOT active


def detect_shell(env: dict[str, str] | None = None) -> str | None:
    """The user's shell (bash/zsh) from ``$SHELL``, or None when it is neither.

    A basename match on $SHELL — the login shell, which is what a new interactive session uses.
    None means "nothing to install here" (not a failure): fish/other shells are out of scope.
    """
    shell = (env if env is not None else os.environ).get("SHELL", "")
    base = Path(shell).name
    return base if base in SUPPORTED_SHELLS else None


def _completion_script(shell: str) -> str | None:
    """The shell source for tmap's completion, or None for an unsupported shell.

    Click's ``.source()`` emits a small bootstrap keyed only on the program name and the trigger
    env var — it does NOT embed the command tree (the tree is queried at completion time by
    re-invoking tmap), so a throwaway command object suffices and the CLI need not be imported here.
    """
    cls = get_completion_class(shell)
    if cls is None:
        return None
    comp = cls(cli=click.Command("tmap"), ctx_args={}, prog_name="tmap", complete_var=_COMPLETE_VAR)
    return comp.source()


def target_path(shell: str, home: Path) -> Path | None:
    """Where a shell auto-loads a user completion for ``tmap`` — no rc edit required.

    bash: bash-completion (v2) lazy-loads ``~/.local/share/bash-completion/completions/<cmd>``.
    zsh:  a functions file named ``_<cmd>`` on ``$fpath``; ``~/.zsh/completions`` is the usual user
          location (it still needs to be on fpath — surfaced by the activation check).
    """
    if shell == "bash":
        return home / ".local" / "share" / "bash-completion" / "completions" / "tmap"
    if shell == "zsh":
        return home / ".zsh" / "completions" / "_tmap"
    return None


def _bash_completion_present() -> bool:
    """True when the bash-completion framework is installed system-wide.

    bash-completion is what lazy-loads a file dropped in the user completions dir, so its presence
    means our script will be picked up with no rc edit. Checked by the standard install locations
    (Debian/Fedora, Homebrew) plus the env dir bash-completion itself honours — never by spawning a
    shell. Absent -> we cannot assume our file is sourced, so the caller prints the manual line."""
    env_dir = os.environ.get("BASH_COMPLETION_USER_DIR")
    candidates = [
        Path("/usr/share/bash-completion/bash_completion"),
        Path("/etc/bash_completion"),
        Path("/usr/local/etc/profile.d/bash_completion.sh"),
        Path("/opt/homebrew/etc/profile.d/bash_completion.sh"),
    ]
    if env_dir:
        candidates.append(Path(env_dir))
    return any(p.exists() for p in candidates)


def _zshrc_puts_dir_on_fpath(home: Path, comp_dir: Path) -> bool:
    """Best-effort: does the user's zsh startup already put ``comp_dir`` on fpath?

    A conservative READ of ~/.zshrc / ~/.zprofile (never a shell spawn, never an edit): true only
    when a line both mentions ``fpath`` and references the completions dir. Uncertain -> False, so
    the caller errs toward printing the activation step rather than a false 'it works'."""
    needles = (str(comp_dir), "~/.zsh/completions", "$HOME/.zsh/completions", ".zsh/completions")
    for rc in (home / ".zshrc", home / ".zprofile"):
        try:
            text = rc.read_text()
        except OSError:
            continue
        for line in text.splitlines():
            if "fpath" in line and any(n in line for n in needles):
                return True
    return False


def _bashrc_sources_completion(home: Path, path: Path) -> bool:
    """Best-effort: does the user's bash startup already source our completion script?

    The same conservative READ as the zsh check (never a shell spawn): true only when a source line
    (``source X`` or ``. X``) names our exact script path. Sourcing the script directly is a
    complete activation on its own — it registers the completion without the bash-completion
    framework — so this is a second, independent way for bash to be genuinely active."""
    needle = str(path)
    for rc in (home / ".bashrc", home / ".bash_profile"):
        try:
            text = rc.read_text()
        except OSError:
            continue
        for raw in text.splitlines():
            line = raw.strip()
            if needle in line and (line.startswith(("source ", ". ")) or " source " in line):
                return True
    return False


def rc_path(shell: str, home: Path) -> Path | None:
    """The startup file whose one line makes an installed completion script actually load.

    This is the ONLY file init ever appends to, and only with the user's explicit yes."""
    if shell == "bash":
        return home / ".bashrc"
    if shell == "zsh":
        return home / ".zshrc"
    return None


def _activation_line(shell: str, path: Path) -> str | None:
    """The bare shell line that activates the completion — no prose, no prefix.

    ONE source of truth: the human-facing hint below wraps this line in an instruction, and
    ``activate_completion`` appends exactly this line to the rc. Keeping them split matters — the
    hint is a sentence ("add to ~/.zshrc: …"), and appending a sentence to a shell rc would be a
    syntax error, not an activation.

    The zsh line is self-sufficient: it re-runs ``compinit`` itself, so it works appended at the END
    of an rc and need not be threaded in before a user's existing compinit."""
    if shell == "bash":
        return f"source {path}"
    if shell == "zsh":
        return f"fpath=({path.parent} $fpath) && autoload -Uz compinit && compinit"
    return None


def _activation(shell: str, home: Path, path: Path) -> tuple[bool, str | None]:
    """(will an interactive shell load ``path``?, the one line to add if not).

    Conservative by design: when it cannot be confirmed, returns not-active WITH the exact step,
    never a hopeful 'active'. A wrong 'you're set up' is worse than a redundant reminder."""
    line = _activation_line(shell, path)
    if shell == "bash":
        if _bash_completion_present() or _bashrc_sources_completion(home, path):
            return True, None
        return False, f"add to ~/.bashrc:  {line}"
    if shell == "zsh":
        if _zshrc_puts_dir_on_fpath(home, path.parent):
            return True, None
        return False, f"add to ~/.zshrc (before 'compinit'):  {line}"
    return False, None


def install_completion(shell: str, home: Path) -> CompletionInstall | None:
    """Write (idempotently) the completion script for ``shell`` to its autoload dir.

    Returns None for an unsupported shell. Idempotent: the file is rewritten only when its content
    differs, so a re-run (including ``--force``) neither duplicates nor errors. Raises OSError only
    on a genuine filesystem failure — the caller reports that honestly rather than swallowing it.
    """
    script = _completion_script(shell)
    path = target_path(shell, home)
    if script is None or path is None:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    wrote = (not path.exists()) or path.read_text() != script
    if wrote:
        path.write_text(script)
    active, hint = _activation(shell, home, path)
    return CompletionInstall(
        shell=shell, path=path, wrote=wrote, active=active, activation_hint=hint
    )


@dataclass(frozen=True)
class CompletionActivation:
    """The outcome of appending the activation line to a shell rc (only ever after a user yes)."""

    shell: str
    rc: Path
    added: bool  # True = the block was appended this run
    already: bool  # True = the marked block was already present, so nothing was written
    error: str | None  # a filesystem failure, reported verbatim; None means it really worked

    @property
    def ok(self) -> bool:
        """Is the rc now carrying the activation line? False means the caller must NOT claim it."""
        return self.error is None


def activate_completion(shell: str, home: Path, path: Path) -> CompletionActivation | None:
    """APPEND a marked activation block to the user's shell rc. Call ONLY on explicit consent.

    Three properties this must hold, in order of how much damage getting them wrong would do:

    * **Append, never rewrite.** The rc is the user's file, often long and hand-tuned; this opens
      it in append mode and adds a fenced block at the end. It never reads-modifies-writes the
      whole file, so there is no path on which an unrelated line is lost.
    * **Idempotent.** If the start marker is already in the rc, nothing is written at all. Running
      ``tmap init`` a dozen times leaves exactly one block.
    * **Honest on failure.** An unreadable/unwritable rc returns the OSError text with
      ``ok`` False; it never reports a success the filesystem did not give, and the caller falls
      back to printing the line for the user to add by hand.

    Returns None for a shell with no rc/activation line (nothing to do, not a failure)."""
    rc = rc_path(shell, home)
    line = _activation_line(shell, path)
    if rc is None or line is None:
        return None
    try:
        existing = rc.read_text() if rc.exists() else ""
    except OSError as exc:
        return CompletionActivation(shell, rc, added=False, already=False, error=str(exc))
    if _MARK_START in existing:
        return CompletionActivation(shell, rc, added=False, already=True, error=None)
    # A leading newline so the block never fuses onto an rc whose last line lacks one.
    block = f"\n{_MARK_START}\n{line}\n{_MARK_END}\n"
    try:
        with rc.open("a", encoding="utf-8") as fh:
            fh.write(block)
    except OSError as exc:
        return CompletionActivation(shell, rc, added=False, already=False, error=str(exc))
    return CompletionActivation(shell, rc, added=True, already=False, error=None)


def completion_check(home: Path, shell: str | None = None) -> tuple[str, bool, str]:
    """A doctor triple (name, ok, detail) for the completion state — honest about activation.

    ok=True only when we are confident ``tmap <tab>`` will work: the script is installed AND the
    shell is set up to load it. When the shell is not bash/zsh there is nothing to install, so it is
    a pass with a note. When installed-but-not-active, ok=False carries the exact line to add — the
    doctor must never present an inert completion as working (the same degrade-must-be-visible rule
    the rest of tmap follows)."""
    shell = shell or detect_shell()
    if shell is None:
        return ("completion", True, "shell is not bash/zsh — nothing to install")
    path = target_path(shell, home)
    if path is None or not path.exists():
        return ("completion", False, f"{shell}: not installed — run `tmap init`")
    active, hint = _activation(shell, home, path)
    if active:
        return ("completion", True, f"{shell}: installed at {path} (active)")
    return ("completion", False, f"{shell}: installed at {path}; not active yet — {hint}")
