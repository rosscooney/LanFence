# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""OUI -> vendor name lookup, from the bundled (curated, offline) vendor table."""

from __future__ import annotations

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
