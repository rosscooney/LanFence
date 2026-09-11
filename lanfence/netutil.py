# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""MAC/IP address helpers shared across LAN Fence."""

from __future__ import annotations

import re

_MAC_RE = re.compile(r"\A([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\Z")


def normalize_mac(value: str) -> str:
    """Canonicalise a MAC address to lowercase, colon-separated form.

    Raises ``ValueError`` if ``value`` is not a well-formed MAC address.
    """

    value = value.strip()
    if not _MAC_RE.match(value):
        raise ValueError(f"not a valid MAC address: {value!r}")
    return value.lower().replace("-", ":")


def oui_of(mac: str) -> str:
    """The 3-octet organisationally-unique-identifier prefix of ``mac``, e.g.
    ``b8:27:eb:12:34:56`` -> ``b8:27:eb``."""

    return ":".join(normalize_mac(mac).split(":")[:3])


def is_locally_administered(mac: str) -> bool:
    """True if the U/L bit (2nd-least-significant bit of the 1st octet) is set.

    Locally administered addresses are not assigned by a vendor - they are
    typically randomized (privacy features on modern phones/laptops) or
    manually set (device cloning, MAC spoofing, many USB-Ethernet gadget
    implants that generate a MAC on the fly).
    """

    first_octet = int(normalize_mac(mac).split(":")[0], 16)
    return bool(first_octet & 0b0000_0010)


def is_multicast(mac: str) -> bool:
    """True if the I/G bit (least-significant bit of the 1st octet) is set."""

    first_octet = int(normalize_mac(mac).split(":")[0], 16)
    return bool(first_octet & 0b0000_0001)
