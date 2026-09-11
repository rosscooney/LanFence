# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Sanitisation for untrusted, device-supplied text.

LAN Fence handles strings that come straight off the wire - DHCP hostnames,
mDNS/NetBIOS names, vendor strings - all attacker-controlled by any device that
joins the network. Those strings end up in the JSON report, the database and
the operator's terminal, so before they are stored or displayed we:

* replace C0/C1 control characters and DEL with U+FFFD (defeats raw ANSI escape
  injection into the operator's terminal),
* collapse newlines / carriage returns to spaces,
* bound the length (defeats amplification via an oversized hostname).
"""

from __future__ import annotations

import re
from typing import Any

# C0 controls except tab, plus DEL and the C1 range.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

DEFAULT_MAX_LEN = 512
IDENTITY_MAX_LEN = 64


def clean_text(value: Any, *, max_len: int = DEFAULT_MAX_LEN) -> Any:
    """Return ``value`` with control characters removed and length bounded.

    Non-string values are returned unchanged. ``None`` stays ``None``.
    """

    if not isinstance(value, str):
        return value
    text = _CONTROL_CHARS.sub("�", value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = text.strip()
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def clean_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """Sanitise every string value (and key) in an attributes mapping."""

    return {clean_text(key, max_len=128): clean_text(val) for key, val in attributes.items()}
