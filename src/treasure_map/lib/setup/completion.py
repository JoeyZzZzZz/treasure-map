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
  * NEVER edit the user's shell rc file. Write to the shell's own autoload directory; if that is
    not enough, PRINT the one line for the user to add — never add it for them.
  * NEVER silently claim success. If the script cannot be generated/written, or the shell will not
    pick it up, that is surfaced (init echo + a doctor check), not swallowed.

bash and zsh only — the vast majority of users. fish and others are added on demand, not pre-built.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import click
from click.shell_completion import get_completion_class

SUPPORTED_SHELLS = ("bash", "zsh")

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


def _activation(shell: str, home: Path, path: Path) -> tuple[bool, str | None]:
    """(will an interactive shell load ``path``?, the one line to add if not).

    Conservative by design: when it cannot be confirmed, returns not-active WITH the exact step,
    never a hopeful 'active'. A wrong 'you're set up' is worse than a redundant reminder."""
    if shell == "bash":
        if _bash_completion_present():
            return True, None
        return False, f"add to ~/.bashrc:  source {path}"
    if shell == "zsh":
        comp_dir = path.parent
        if _zshrc_puts_dir_on_fpath(home, comp_dir):
            return True, None
        return False, (
            f"add to ~/.zshrc (before 'compinit'):  "
            f"fpath=({comp_dir} $fpath) && autoload -Uz compinit && compinit"
        )
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
