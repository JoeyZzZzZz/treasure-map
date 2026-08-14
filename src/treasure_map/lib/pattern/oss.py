# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""OSS / third-party component exclusion.

Lesson learned from the detection spike: without excluding OSS components, a scan
drowns in self-matches. Exclusion is data-driven first (a binary recorded in the
components table is a known third-party component) and falls back to a list of generic,
public OSS project names plus the conventional lib* / shared-object heuristics. Custom,
unknown binaries — the analysis targets — are kept by default.
"""

from __future__ import annotations

import re

# Public, well-known OSS project names (NOT vendor brands). Used only as a fallback for
# binaries that the components table does not already identify as third-party.
GENERIC_OSS_NAMES: frozenset[str] = frozenset(
    {
        "busybox",
        "openssl",
        "zlib",
        "curl",
        "dnsmasq",
        "dropbear",
        "hostapd",
        "wpa_supplicant",
        "lighttpd",
        "uhttpd",
        "openvpn",
        "iptables",
        "ebtables",
        "miniupnpd",
        "pppd",
        "ntpd",
        "telnetd",
        "vsftpd",
        "samba",
        "smbd",
        "expat",
        "sqlite3",
    }
)

_SO_SUFFIX = re.compile(r"\.so(\.\d+)*$")
_TRAILING_VERSION = re.compile(r"[-_]?\d+(\.\d+)*$")


def _stem(binary_name: str) -> str:
    """Reduce a binary name to a comparable stem: basename, no .so, no version tail."""
    base = binary_name.rsplit("/", 1)[-1].lower()
    base = _SO_SUFFIX.sub("", base)
    return _TRAILING_VERSION.sub("", base)


def is_oss_binary(binary_name: str, *, known_components: set[str]) -> bool:
    """True if binary_name is a known OSS/third-party component (to be excluded).

    known_components are binary names the components table already identifies as
    third-party (data-driven, neutral). The name heuristics are a fallback only.
    """
    if binary_name in known_components:
        return True
    stem = _stem(binary_name)
    if stem in GENERIC_OSS_NAMES:
        return True
    # Conventional shared-library naming: lib* objects are third-party by convention.
    return stem.startswith("lib")
