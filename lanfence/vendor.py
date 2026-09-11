# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""OUI -> vendor name lookup, from the bundled (offline) vendor table.

The table is a snapshot of the IEEE's public MA-L (24-bit block) OUI
registry - the only registry tier where a plain 3-octet OUI maps to exactly
one organisation (the finer-grained MA-M/MA-S tiers reassign parts of one
OUI-24 to several different organisations, which a 3-octet key can't
represent). ``parse_ieee_oui_csv`` turns IEEE's CSV
(https://standards-oui.ieee.org/oui/oui.csv) into this module's tab-separated
format; ``lanfence vendor-refresh`` (see ``lanfence.cli``) uses it to let an
operator refresh the table on demand without a new LAN Fence release.
"""

from __future__ import annotations

import csv
import io
from functools import lru_cache
from importlib import resources
from pathlib import Path

from lanfence.netutil import is_locally_administered, oui_of

_PACKAGED_TABLE = "oui_vendors.txt"


def _parse(text: str) -> dict[str, str]:
    table: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        prefix, _, name = line.partition("\t")
        if not name:
            continue
        table[prefix.strip().upper()] = name.strip()
    return table


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    text = resources.files("lanfence.data").joinpath(_PACKAGED_TABLE).read_text(encoding="utf-8")
    return _parse(text)


def lookup_vendor(mac: str, *, extra_file: Path | str | None = None) -> str | None:
    """Best-effort vendor name for ``mac``, or ``None`` if unknown.

    Returns ``None`` (rather than a vendor name) for locally administered
    addresses - the OUI there carries no vendor meaning, and a lookup would
    coincidentally hit an unrelated real vendor's block.
    """

    if is_locally_administered(mac):
        return None
    prefix = oui_of(mac).upper()
    table = dict(_table())
    if extra_file is not None:
        path = Path(extra_file)
        if path.is_file():
            table.update(_parse(path.read_text(encoding="utf-8")))
    return table.get(prefix)


def parse_ieee_oui_csv(text: str) -> dict[str, str]:
    """Parse IEEE's MA-L OUI registry CSV into ``{"XX:XX:XX": "Vendor Name"}``.

    Rows outside the ``MA-L`` registry tier, and any row whose ``Assignment``
    isn't a well-formed 6-hex-digit OUI, are skipped rather than raising -
    IEEE's own CSV is not something LAN Fence controls the shape of.
    """

    table: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        if (row.get("Registry") or "").strip() != "MA-L":
            continue
        raw_oui = (row.get("Assignment") or "").strip().upper()
        if len(raw_oui) != 6 or any(c not in "0123456789ABCDEF" for c in raw_oui):
            continue
        name = " ".join((row.get("Organization Name") or "").split())
        if not name:
            continue
        oui = ":".join((raw_oui[0:2], raw_oui[2:4], raw_oui[4:6]))
        table[oui] = name
    return table


def format_vendor_table(table: dict[str, str]) -> str:
    """Render ``table`` back into this module's tab-separated file format."""

    return "".join(f"{oui}\t{name}\n" for oui, name in sorted(table.items()))
