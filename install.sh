#!/bin/sh
# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
#
# Install tmap (PyPI: tmap-agents) with uv, then start `tmap init`.
#
#   curl -LsSf https://github.com/JoeyZzZzZz/treasure-map/releases/latest/download/install.sh | sh
#
# POSIX sh (dash runs it): no pipefail, no [[ ]], no arrays. Everything sits inside one { } block
# so a download cut short executes nothing. Your shell rc is never edited: uv is installed with
# UV_NO_MODIFY_PATH=1, and a missing PATH entry is printed for you to add.
{
set -eu

TMAP_VERSION="__TMAP_VERSION__"
DRY_RUN=0
NO_INIT=0

say() { printf '%s\n' "$*"; }
die() { printf 'tmap install: %s\n' "$*" >&2; exit 1; }

usage() {
    say "usage: install.sh [--version X.Y.Z] [--dry-run] [--no-init]"
    say "  --version X.Y.Z  install this tmap version (default: $TMAP_VERSION)"
    say "  --dry-run        print the plan and change nothing"
    say "  --no-init        do not start 'tmap init' afterwards"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || die "--version needs a value"
            TMAP_VERSION="$2"
            shift 2
            ;;
        --version=*)
            TMAP_VERSION="${1#--version=}"
            shift
            ;;
        --dry-run) DRY_RUN=1; shift ;;
        --no-init) NO_INIT=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

case "$TMAP_VERSION" in
    __TMAP_*) die "this install.sh carries no version; download it from a release, or pass --version" ;;
esac
if ! printf '%s\n' "$TMAP_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([a-z0-9.]+)?$'; then
    die "not a version: $TMAP_VERSION (expected X.Y.Z)"
fi

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS-$ARCH" in
    Linux-x86_64|Linux-amd64) PLATFORM="linux-x86_64" ;;
    Darwin-arm64|Darwin-aarch64) PLATFORM="darwin-arm64" ;;
    Darwin-x86_64) PLATFORM="darwin-x86_64" ;;
    Linux-aarch64|Linux-arm64)
        die "linux-aarch64 is not supported: Ghidra ships no linux_arm_64 decompiler and BinDiff has no arm64 Linux build" ;;
    MINGW*|MSYS*|CYGWIN*|Windows*)
        die "native Windows is not supported: use WSL2" ;;
    *) die "$OS-$ARCH: no supported toolchain for this platform" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required"

find_uv() {
    if command -v uv >/dev/null 2>&1; then
        command -v uv
        return 0
    fi
    for d in "${UV_INSTALL_DIR:-}" "${XDG_BIN_HOME:-}" "${XDG_DATA_HOME:+$XDG_DATA_HOME/../bin}" \
             "$HOME/.local/bin" "$HOME/.cargo/bin"; do
        if [ -n "$d" ] && [ -x "$d/uv" ]; then
            printf '%s\n' "$d/uv"
            return 0
        fi
    done
    return 1
}

UV="$(find_uv || true)"
if [ -n "$UV" ]; then
    UV_STATE="found at $UV"
else
    UV_STATE="not found -> will install (astral.sh installer, UV_NO_MODIFY_PATH=1: your shell rc is not edited)"
fi

if [ "$NO_INIT" -eq 0 ] && (exec </dev/tty) 2>/dev/null && [ -t 1 ]; then
    NEXT="tmap init (terminal detected)"
else
    NEXT="print 'next: tmap init'"
fi

say "tmap install plan"
say "  Version  : $TMAP_VERSION"
say "  Platform : $PLATFORM"
say "  uv       : $UV_STATE"
say "  Command  : uv tool install --python 3.11 tmap-agents==$TMAP_VERSION   (uv-managed Python only)"
say "  Next     : $NEXT"

if [ "$DRY_RUN" -eq 1 ]; then
    say "dry run: nothing changed"
    exit 0
fi

if [ -z "$UV" ]; then
    curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh
    UV="$(find_uv || true)"
    [ -n "$UV" ] || die "uv was installed but cannot be found; see https://docs.astral.sh/uv/"
fi

UV_PYTHON_PREFERENCE=only-managed "$UV" tool install --force --python 3.11 "tmap-agents==$TMAP_VERSION"

BIN_DIR="$("$UV" tool dir --bin)"
BIN="$BIN_DIR/tmap"
[ -x "$BIN" ] || die "tmap was not installed at $BIN"
GOT="$("$BIN" --version)"
[ "$GOT" = "tmap $TMAP_VERSION" ] || die "installed tmap reports '$GOT', expected 'tmap $TMAP_VERSION'"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say "add $BIN_DIR to PATH (or run: uv tool update-shell)" ;;
esac

if [ "$NO_INIT" -eq 0 ] && (exec </dev/tty) 2>/dev/null && [ -t 1 ]; then
    say "tmap $TMAP_VERSION installed. Starting tmap init…"
    exec "$BIN" init </dev/tty
fi
say "tmap $TMAP_VERSION installed."
say "next: tmap init"
}
