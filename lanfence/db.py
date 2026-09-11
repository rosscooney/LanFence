# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Persistent SQLite store of every device LAN Fence has ever seen.

Four tables: ``devices`` holds the current state of each MAC address (first
seen, last seen, online/offline); ``events`` is an append-only log of
lifecycle transitions (new / reappeared / disconnected) used by ``lanfence
report``; ``alert_log`` tracks the last external-alert dispatch per MAC, used
by :meth:`DeviceStore.due_for_alert` to cool down repeated alerts for a
flapping device; ``device_review`` tracks the ``lanfence review`` state
(snoozed/investigating) per MAC, used by ``lanfence devices``/``device``/
``review``. Trust itself is *not* stored here - it lives in the YAML
allowlist (see ``lanfence/allowlist.py``); this table only tracks the
review workflow around a still-untrusted device.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from lanfence.models import SEVERITIES, Device, DeviceEvent, EventType, ReviewState, Severity
from lanfence.netutil import normalize_mac

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

CREATE TABLE IF NOT EXISTS alert_log (
    mac TEXT PRIMARY KEY,
    last_alerted_at TEXT NOT NULL,
    last_severity TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_review (
    mac TEXT PRIMARY KEY,
    state TEXT NOT NULL DEFAULT 'pending',
    notes TEXT,
    snoozed_until TEXT,
    updated_at TEXT NOT NULL
);
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

    def events_for(self, mac: str, *, since: datetime | None = None) -> list[DeviceEvent]:
        """One device's lifecycle timeline, oldest first.

        Note this is *only* the log of connect/reappear/disconnect
        transitions - a routine "still online, nothing changed" sighting
        records no event, so a device's IP/hostname may have changed one or
        more times without a corresponding timeline entry. It is not a
        complete history of every address a MAC has ever held.
        """

        mac = normalize_mac(mac)
        if since is not None:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE mac = ? AND timestamp >= ? ORDER BY timestamp ASC",
                (mac, _iso(since)),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE mac = ? ORDER BY timestamp ASC", (mac,)
            ).fetchall()
        return [
            DeviceEvent(
                mac=row["mac"], event_type=row["event_type"], timestamp=_parse_dt(row["timestamp"]),
                ip=row["ip"], hostname=row["hostname"],
            )
            for row in rows
        ]

    def get_review(self, mac: str) -> ReviewState:
        """The persisted review state for ``mac`` - ``pending``/unreviewed if
        it has never been snoozed or flagged for investigation."""

        mac = normalize_mac(mac)
        row = self._conn.execute(
            "SELECT state, notes, snoozed_until, updated_at FROM device_review WHERE mac = ?", (mac,)
        ).fetchone()
        if row is None:
            return ReviewState(mac=mac)
        return ReviewState(
            mac=mac,
            state=row["state"],
            notes=row["notes"],
            snoozed_until=_parse_dt(row["snoozed_until"]) if row["snoozed_until"] else None,
            updated_at=_parse_dt(row["updated_at"]),
        )

    def _upsert_review(
        self, mac: str, *, state: str, notes: str | None, snoozed_until: datetime | None, updated_at: datetime
    ) -> None:
        self._conn.execute(
            "INSERT INTO device_review (mac, state, notes, snoozed_until, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(mac) DO UPDATE SET state = excluded.state, notes = excluded.notes, "
            "snoozed_until = excluded.snoozed_until, updated_at = excluded.updated_at",
            (mac, state, notes, _iso(snoozed_until) if snoozed_until else None, _iso(updated_at)),
        )
        self._conn.commit()

    def set_snoozed(
        self, mac: str, *, until: datetime, notes: str | None = None, updated_at: datetime
    ) -> ReviewState:
        """Suppress external alerts for ``mac`` until ``until``.

        Only ever throttles alert *dispatch* (see
        :func:`lanfence.engine.filter_snoozed`) - findings, events and CLI/
        JSON output are unaffected. ``notes`` left as ``None`` preserves any
        notes already on file rather than blanking them.
        """

        mac = normalize_mac(mac)
        if notes is None:
            notes = self.get_review(mac).notes
        self._upsert_review(mac, state="snoozed", notes=notes, snoozed_until=until, updated_at=updated_at)
        return self.get_review(mac)

    def set_investigating(self, mac: str, *, notes: str | None = None, updated_at: datetime) -> ReviewState:
        """Flag ``mac`` for investigation - does not trust it or suppress alerts."""

        mac = normalize_mac(mac)
        self._upsert_review(mac, state="investigating", notes=notes, snoozed_until=None, updated_at=updated_at)
        return self.get_review(mac)

    def clear_review(self, mac: str) -> None:
        """Remove any review flag/snooze for ``mac``. Does not touch the
        allowlist - see ``lanfence allow --remove`` for untrusting a device."""

        mac = normalize_mac(mac)
        self._conn.execute("DELETE FROM device_review WHERE mac = ?", (mac,))
        self._conn.commit()

    def is_snoozed(self, mac: str, *, now: datetime) -> bool:
        """Whether ``mac`` is *currently* snoozed - an expired snooze reads
        as not-snoozed without needing any write to expire it."""

        review = self.get_review(mac)
        return review.state == "snoozed" and review.snoozed_until is not None and review.snoozed_until > now

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

    def due_for_alert(
        self, mac: str, severity: Severity, *, now: datetime, cooldown_seconds: float
    ) -> bool:
        """Whether an external alert for ``mac`` at ``severity`` should fire now.

        Checks and records in one call, so a caller can't race between "may I
        alert" and "record that I did." Returns ``True`` - and upserts
        ``alert_log`` - when there is no prior record, the cooldown has
        elapsed since the last dispatch, or ``severity`` outranks what was
        last alerted (an escalation always bypasses the cooldown). Returns
        ``False`` without touching the row otherwise.
        ``cooldown_seconds <= 0`` always returns ``True`` (rate limiting off).
        """

        if cooldown_seconds <= 0:
            return True

        row = self._conn.execute(
            "SELECT last_alerted_at, last_severity FROM alert_log WHERE mac = ?", (mac,)
        ).fetchone()

        if row is not None:
            elapsed = (now - _parse_dt(row["last_alerted_at"])).total_seconds()
            escalated = SEVERITIES.index(severity) > SEVERITIES.index(row["last_severity"])
            if elapsed < cooldown_seconds and not escalated:
                return False

        self._conn.execute(
            "INSERT INTO alert_log (mac, last_alerted_at, last_severity) VALUES (?, ?, ?) "
            "ON CONFLICT(mac) DO UPDATE SET last_alerted_at = excluded.last_alerted_at, "
            "last_severity = excluded.last_severity",
            (mac, _iso(now), severity),
        )
        self._conn.commit()
        return True

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
