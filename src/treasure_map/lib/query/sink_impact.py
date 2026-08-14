# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""Sink-impact tier config + controllability markers — data-driven and extensible.

The {sink_class -> impact tier} map is DATA, not code branches. Adding a new sink type (a path
sink, an nvram_set sink, ...) is one row in ``DEFAULT_SINK_IMPACT`` — the triage sort logic, the
demotion iron law, and the composite key never change. ``sink_class`` is an OPEN value set:
an unmapped class ranks at ``DEFAULT_IMPACT_TIER`` (lowest, but STILL ranked — never dropped), and
the sort treats any class uniformly by its tier.

The default tier order (``cmd = fmt_string > copy > log``) is a visible, OVERRIDABLE judgement,
not a hidden constant: an agent supplies its own order via ``parse_impact_order`` and the
whole map is replaced. The ordering *structure* (impact then controllability) is fixed elsewhere;
only the impact *values* here are overridable.
"""

from __future__ import annotations

# Impact tiers — higher = higher potential impact. Ordinals only, so a future tier slots in by
# magnitude without touching the sort. cmd / fmt_string are both RCE-class interpreters (highest);
# copy is memory-corruption (middle); log / string-format is lowest.
IMPACT_HIGH = 3
IMPACT_MEDIUM = 2
IMPACT_LOW = 1
# An unmapped / unknown sink_class ranks here: the lowest tier, but it is STILL ranked and listed —
# an unrecognized sink is never silently dropped (open-value-set contract).
DEFAULT_IMPACT_TIER = 0

# {sink_class -> impact tier}. THE extension point (step 2): a new sink type is one row here.
DEFAULT_SINK_IMPACT: dict[str, int] = {
    "cmd": IMPACT_HIGH,  # system / popen / exec* / doSystem — command execution (RCE)
    "fmt_string": IMPACT_HIGH,  # controllable printf-family format string — info leak / write
    # fopen / open / unlink / rename / … — a controllable path enables directory traversal or
    # arbitrary file read/write/delete (write a startup script -> RCE; read /etc/* -> leak). Placed
    # HIGH — an OVERRIDABLE judgement (an agent may split write>read via --impact-order once mode is
    # classified), not a magnitude-of-harm claim.
    "path_sink": IMPACT_HIGH,
    "copy": IMPACT_MEDIUM,  # memcpy / strcpy / strncpy — buffer overflow
    "format": IMPACT_LOW,  # plain string formatting into a buffer
    "log": IMPACT_LOW,  # syslog and similar — lowest
}


def impact_tier(sink_class: str, overrides: dict[str, int] | None = None) -> int:
    """Impact tier for a sink_class. Any class not in the map (open value set) falls to
    DEFAULT_IMPACT_TIER (lowest, still ranked). ``overrides`` (from ``parse_impact_order``) replaces
    the default map."""
    table = overrides if overrides is not None else DEFAULT_SINK_IMPACT
    return table.get(sink_class, DEFAULT_IMPACT_TIER)


def parse_impact_order(spec: str) -> dict[str, int]:
    """Parse an agent override like ``"cmd=fmt_string,copy,log"`` into a {sink_class -> tier} map.

    A comma separates DESCENDING tiers (first group highest); an ``=`` co-ranks classes into the
    same tier (so ``cmd=fmt_string`` keeps them equal). Classes not named fall to the default tier
    when looked up — the agent's stated order wins, nothing is invented. An empty / all-blank spec
    yields an empty map (caller treats that as 'use the default')."""
    groups = [g.strip() for g in spec.split(",") if g.strip()]
    out: dict[str, int] = {}
    n = len(groups)
    for i, group in enumerate(groups):
        tier = n - i  # first group gets the highest tier
        for cls in group.split("="):
            cls = cls.strip()
            if cls:
                out[cls] = tier
    return out


# --- nvram controllability combo -------------------------------------------------------------
# Callees whose return value is an nvram key's stored value. When a sink argument's def-use
# provenance is a call_return from one of these, the KEY is the getter's first constant string
# argument (``const_args[0]``); its web-settability (router_defaults) drives the controllability
# annotation (fact transport). Extend this set as new getters appear; it is a mechanism
# list, not a verdict.
NVRAM_GETTERS: frozenset[str] = frozenset(
    {
        "nvram_get",
        "nvram_safe_get",
        "nvram_bufget",
        "nvram_get_int",
        "nvram_get_value",
        "nvram_get_state",
        "acosNvramConfig_get",
        "acosNvramConfig_read",
        "envram_get",
        "envram_safe_get",
    }
)

# --- controllability markers (blocking_mechanism notes) -----------------------------------------
# Notes that PROVE the sink's dangerous value is a compile-time constant (not attacker-influenced).
# This is the ONLY 'proven-safe' controllability the map can assert this phase: it is
# what lets the default lens sink constant command junk out of the first screen. Extensible.
PROVABLY_CONSTANT_MARKERS: frozenset[str] = frozenset(
    {
        "const_sink_arg",  # sink's dangerous arg is a fixed .rodata string constant
        "caller_constant",  # a constant supplied by the sole caller
        "const_size",  # copy length is a literal constant
        "sizeof_bound",  # copy length is a sizeof (non-controllable)
    }
)
# Notes that constrain the value's charset / numeric shape: not free, but NOT provably constant
# either (so they never trigger the sink-out-of-first-screen demotion — only 'constant' does).
CONSTRAINED_MARKERS: frozenset[str] = frozenset(
    {
        "charset_constrained",  # value constrained to a safe charset (MAC / IP / base64 form)
        "numeric_sanitized",  # a numeric validator on the path
    }
)
