# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""The allowlist of devices you trust (``lanfence allow``).

Findings about an allowlisted device are downgraded to ``info`` so your own
router, phones and laptops stop showing up as "unknown device" every time they
reconnect. This is just data - allowlisting a MAC does not verify it, and MAC
addresses are trivially spoofed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from lanfence.fsutil import atomic_write
from lanfence.logging_config import get_logger
from lanfence.netutil import normalize_mac

log = get_logger("allowlist")


@dataclass
class AllowEntry:
    mac: str
    name: str
    notes: str = ""

    def as_dict(self) -> dict:
        row = {"mac": self.mac, "name": self.name}
        if self.notes:
            row["notes"] = self.notes
        return row


class Allowlist:
    def __init__(self, entries: list[AllowEntry], path: Path | None = None) -> None:
        self.entries = entries
        self.path = path

    def __len__(self) -> int:
        return len(self.entries)

    @classmethod
    def load(cls, path: Path | str | None) -> "Allowlist":
        if path is None:
            return cls([], None)
        path = Path(path)
        if not path.is_file():
            return cls([], path)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        entries: list[AllowEntry] = []
        for row in data.get("allow", []) or []:
            try:
                entries.append(
                    AllowEntry(
                        mac=normalize_mac(str(row["mac"])),
                        name=str(row.get("name") or "unnamed"),
                        notes=str(row.get("notes") or ""),
                    )
                )
            except (KeyError, TypeError, ValueError):
                log.warning("skipping malformed allowlist entry: %r", row)
        return cls(entries, path)

    def save(self) -> None:
        if self.path is None:
            raise ValueError("allowlist has no path to save to")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = yaml.safe_dump({"allow": [e.as_dict() for e in self.entries]}, sort_keys=False)
        atomic_write(
            self.path,
            "# LAN Fence allowlist - devices you trust; their findings are\n"
            "# downgraded to info. A MAC address is trivially spoofed, so this is\n"
            "# a mute button, not proof of identity.\n" + body,
            mode=0o644,
        )

    def match(self, mac: str) -> AllowEntry | None:
        norm = normalize_mac(mac)
        for entry in self.entries:
            if entry.mac == norm:
                return entry
        return None

    def add(self, mac: str, name: str, notes: str = "") -> AllowEntry:
        norm = normalize_mac(mac)
        entry = AllowEntry(norm, name, notes)
        self.entries = [e for e in self.entries if e.mac != norm]
        self.entries.append(entry)
        return entry

    def remove(self, mac: str) -> AllowEntry | None:
        norm = normalize_mac(mac)
        existing = self.match(norm)
        if existing is not None:
            self.entries = [e for e in self.entries if e.mac != norm]
        return existing
