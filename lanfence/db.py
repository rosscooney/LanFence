# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Persistent SQLite store of every device LAN Fence has ever seen.

Two tables: ``devices`` holds the current state of each MAC address (first
seen, last seen, online/offline); ``events`` is an append-only log of
lifecycle transitions (new / reappeared / disconnected) used by ``lanfence
report``.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from lanfence.models import Device, DeviceEvent, EventType

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    status TEXT NOT NULL DEFAULT 'online',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    ip TEXT,
    hostname TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_mac ON events (mac);
"""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _row_to_device(row: sqlite3.Row) -> Device:
    return Device(
        mac=row["mac"],
        ip=row["ip"],
        hostname=row["hostname"],
        vendor=row["vendor"],
        status=row["status"],
        first_seen=_parse_dt(row["first_seen"]),
        last_seen=_parse_dt(row["last_seen"]),
    )


class DeviceStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "DeviceStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def get_device(self, mac: str) -> Device | None:
        row = self._conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return _row_to_device(row) if row else None

    def all_devices(self) -> list[Device]:
        rows = self._conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        return [_row_to_device(row) for row in rows]

    def online_devices(self) -> list[Device]:
        return [d for d in self.all_devices() if d.status == "online"]

    def record_event(self, event: DeviceEvent) -> None:
        self._conn.execute(
            "INSERT INTO events (mac, event_type, timestamp, ip, hostname) VALUES (?, ?, ?, ?, ?)",
            (event.mac, event.event_type, _iso(event.timestamp), event.ip, event.hostname),
        )
        self._conn.commit()

    def events_since(self, since: datetime) -> list[DeviceEvent]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp ASC",
            (_iso(since),),
        ).fetchall()
        return [
            DeviceEvent(
                mac=row["mac"],
                event_type=row["event_type"],
                timestamp=_parse_dt(row["timestamp"]),
                ip=row["ip"],
                hostname=row["hostname"],
            )
            for row in rows
        ]

    def observe(
        self,
        *,
        mac: str,
        ip: str | None,
        hostname: str | None,
        vendor: str | None,
        seen_at: datetime,
    ) -> tuple[Device, EventType | None]:
        """Record that ``mac`` was seen alive at ``seen_at``.

        Returns the updated :class:`Device` and, if this observation is a
        lifecycle transition, the corresponding event type (``new_device`` the
        first time a MAC is ever seen, ``reappeared`` if it had been marked
        offline, or ``None`` for a routine still-online refresh).
        """

        existing = self.get_device(mac)
        event_type: EventType | None = None

        if existing is None:
            event_type = "new_device"
            self._conn.execute(
                "INSERT INTO devices (mac, ip, hostname, vendor, status, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, 'online', ?, ?)",
                (mac, ip, hostname, vendor, _iso(seen_at), _iso(seen_at)),
            )
        else:
            if existing.status == "offline":
                event_type = "reappeared"
            self._conn.execute(
                "UPDATE devices SET ip = ?, hostname = ?, vendor = COALESCE(?, vendor), "
                "status = 'online', last_seen = ? WHERE mac = ?",
                (ip, hostname, vendor, _iso(seen_at), mac),
            )
        self._conn.commit()

        device = self.get_device(mac)
        assert device is not None
        if event_type is not None:
            self.record_event(
                DeviceEvent(mac=mac, event_type=event_type, timestamp=seen_at, ip=ip, hostname=hostname)
            )
        return device, event_type

    def mark_offline(self, still_online_macs: set[str], *, as_of: datetime) -> list[DeviceEvent]:
        """Mark every currently-online device NOT in ``still_online_macs`` offline.

        Call this once per completed active-scan sweep so devices that stopped
        responding are recorded as disconnected.
        """

        events: list[DeviceEvent] = []
        for device in self.online_devices():
            if device.mac in still_online_macs:
                continue
            self._conn.execute(
                "UPDATE devices SET status = 'offline', last_seen = ? WHERE mac = ?",
                (_iso(as_of), device.mac),
            )
            event = DeviceEvent(mac=device.mac, event_type="disconnected", timestamp=as_of,
                                 ip=device.ip, hostname=device.hostname)
            self.record_event(event)
            events.append(event)
        self._conn.commit()
        return events
