# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Persistent SQLite store of every device LAN Fence has ever seen.

Four tables: ``devices`` holds the current state of each MAC address (first
seen, last seen, online/offline, and - for the offline-grace-period feature -
its consecutive-missed-scan count and discovery provenance); ``events`` is an
append-only log of lifecycle transitions (new / reappeared / disconnected)
used by ``lanfence report``; ``alert_log`` tracks the last external-alert
dispatch per MAC, used by :meth:`DeviceStore.due_for_alert` to cool down
repeated alerts for a flapping device; ``device_review`` tracks the
``lanfence review`` state (snoozed/investigating) per MAC, used by ``lanfence
devices``/``device``/``review``. Trust itself is *not* stored here - it lives
in the YAML allowlist (see ``lanfence/allowlist.py``); this table only tracks
the review workflow around a still-untrusted device.

``devices``' ``missed_scans``/``seen_via_ipv4``/``seen_via_ipv6``/
``last_interface``/``ipv4_subnet`` columns are provenance for
:meth:`DeviceStore.mark_offline` - see its docstring for how they gate an
offline transition. A row from before this feature existed has all of them
at their defaults (0/0/0/NULL/NULL), which reads as "no known coverage yet";
:meth:`mark_offline` treats that conservatively (never a miss) until a fresh
sighting establishes real provenance, rather than guessing.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from lanfence.models import SEVERITIES, Device, DeviceEvent, EventType, PresenceState, ReviewState, Severity
from lanfence.netutil import normalize_mac

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    status TEXT NOT NULL DEFAULT 'online',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    missed_scans INTEGER NOT NULL DEFAULT 0,
    seen_via_ipv4 INTEGER NOT NULL DEFAULT 0,
    seen_via_ipv6 INTEGER NOT NULL DEFAULT 0,
    last_interface TEXT,
    ipv4_subnet TEXT
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

CREATE TABLE IF NOT EXISTS device_presence (
    mac TEXT PRIMARY KEY,
    policy TEXT NOT NULL DEFAULT 'unspecified',
    offline_after_seconds REAL,
    availability_alerted INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


#: Columns added after the initial release of each table, applied to an
#: existing (pre-upgrade) database idempotently - SQLite has no
#: ``ADD COLUMN IF NOT EXISTS``, so :func:`_ensure_columns` checks
#: ``PRAGMA table_info`` itself before altering. A brand-new database
#: already has every column via ``_SCHEMA`` above, so this is a no-op there.
_MIGRATED_COLUMNS: dict[str, dict[str, str]] = {
    "devices": {
        "missed_scans": "missed_scans INTEGER NOT NULL DEFAULT 0",
        "seen_via_ipv4": "seen_via_ipv4 INTEGER NOT NULL DEFAULT 0",
        "seen_via_ipv6": "seen_via_ipv6 INTEGER NOT NULL DEFAULT 0",
        "last_interface": "last_interface TEXT",
        "ipv4_subnet": "ipv4_subnet TEXT",
    },
}


def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    for name, decl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {decl}")


def _path_covered(
    row: sqlite3.Row, *, ipv4_covered: bool, ipv4_subnet: str | None, ipv6_covered: bool, interface: str | None,
) -> bool:
    """Whether a sweep with this coverage actually examined ``row``'s known
    discovery path(s) - shared eligibility rule for both
    :meth:`DeviceStore.mark_offline` (an eligible miss) and
    :meth:`DeviceStore.evaluate_availability` (an eligible absence check).
    See :meth:`DeviceStore.mark_offline` for the full rationale."""

    seen_via_ipv4 = bool(row["seen_via_ipv4"])
    seen_via_ipv6 = bool(row["seen_via_ipv6"])
    if not (seen_via_ipv4 or seen_via_ipv6):
        return False  # no known coverage yet - conservative no-op

    interface_ok = interface is None or row["last_interface"] is None or row["last_interface"] == interface
    subnet_ok = ipv4_subnet is None or row["ipv4_subnet"] is None or row["ipv4_subnet"] == ipv4_subnet
    ipv4_ok = (not seen_via_ipv4) or (ipv4_covered and interface_ok and subnet_ok)
    ipv6_ok = (not seen_via_ipv6) or (ipv6_covered and interface_ok)
    return ipv4_ok and ipv6_ok


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
        for table, columns in _MIGRATED_COLUMNS.items():
            _ensure_columns(self._conn, table, columns)
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

    def events_between(
        self, start: datetime, end: datetime, *, event_type: str | None = None
    ) -> list[DeviceEvent]:
        """Every event with ``start <= timestamp <= end`` (inclusive both
        ends), oldest first - an explicit, indexed range query (see
        ``idx_events_timestamp``) rather than loading all history and
        filtering in Python. Used by ``lanfence digest`` for its window.
        """

        if event_type is not None:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ? AND event_type = ? "
                "ORDER BY timestamp ASC",
                (_iso(start), _iso(end), event_type),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC",
                (_iso(start), _iso(end)),
            ).fetchall()
        return [
            DeviceEvent(
                mac=row["mac"], event_type=row["event_type"], timestamp=_parse_dt(row["timestamp"]),
                ip=row["ip"], hostname=row["hostname"],
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

    def get_presence(self, mac: str) -> PresenceState:
        """The persisted presence policy for ``mac`` - ``unspecified`` if it
        has never had one set. Separate from trust and from review state."""

        mac = normalize_mac(mac)
        row = self._conn.execute(
            "SELECT policy, offline_after_seconds, availability_alerted, updated_at "
            "FROM device_presence WHERE mac = ?",
            (mac,),
        ).fetchone()
        if row is None:
            return PresenceState(mac=mac)
        return PresenceState(
            mac=mac,
            policy=row["policy"],
            offline_after_seconds=row["offline_after_seconds"],
            availability_alerted=bool(row["availability_alerted"]),
            updated_at=_parse_dt(row["updated_at"]),
        )

    def _upsert_presence(
        self, mac: str, *, policy: str, offline_after_seconds: float | None,
        availability_alerted: bool, updated_at: datetime,
    ) -> None:
        self._conn.execute(
            "INSERT INTO device_presence (mac, policy, offline_after_seconds, availability_alerted, updated_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(mac) DO UPDATE SET policy = excluded.policy, "
            "offline_after_seconds = excluded.offline_after_seconds, "
            "availability_alerted = excluded.availability_alerted, updated_at = excluded.updated_at",
            (mac, policy, offline_after_seconds, int(availability_alerted), _iso(updated_at)),
        )
        self._conn.commit()

    def set_presence_policy(self, mac: str, policy: str, *, updated_at: datetime) -> PresenceState:
        """Set ``mac``'s presence policy (see :data:`lanfence.models.PresencePolicyName`).

        Moving *away* from ``always-on`` clears any per-device
        ``--offline-after`` override and any pending availability-alert
        episode state - there's nothing for either to mean once the device
        is no longer being watched for sustained absence, and switching back
        to ``always-on`` later should start a clean episode rather than
        instantly firing on stale state. Never emits a finding or event
        itself - purely a policy edit.
        """

        mac = normalize_mac(mac)
        if policy == "always-on":
            current = self.get_presence(mac)
            self._upsert_presence(
                mac, policy=policy, offline_after_seconds=current.offline_after_seconds,
                availability_alerted=current.availability_alerted, updated_at=updated_at,
            )
        else:
            self._upsert_presence(
                mac, policy=policy, offline_after_seconds=None,
                availability_alerted=False, updated_at=updated_at,
            )
        return self.get_presence(mac)

    def set_offline_after(self, mac: str, seconds: float | None, *, updated_at: datetime) -> PresenceState:
        """Set (or, with ``seconds=None``, clear back to the global default)
        the per-device availability-alert delay override. Only meaningful
        for an ``always-on`` device; does not itself change the policy."""

        mac = normalize_mac(mac)
        current = self.get_presence(mac)
        self._upsert_presence(
            mac, policy=current.policy, offline_after_seconds=seconds,
            availability_alerted=current.availability_alerted, updated_at=updated_at,
        )
        return self.get_presence(mac)

    def set_availability_alerted(self, mac: str, alerted: bool, *, updated_at: datetime) -> None:
        """Record whether an availability (absence) finding has already
        fired for ``mac``'s current offline episode - set ``True`` when one
        fires, and back to ``False`` on recovery (see
        :func:`lanfence.engine.process_sighting`), so a restart never
        duplicates either and a recovery only ever follows a real alert."""

        mac = normalize_mac(mac)
        current = self.get_presence(mac)
        self._upsert_presence(
            mac, policy=current.policy, offline_after_seconds=current.offline_after_seconds,
            availability_alerted=alerted, updated_at=updated_at,
        )

    def observe(
        self,
        *,
        mac: str,
        ip: str | None,
        hostname: str | None,
        vendor: str | None,
        seen_at: datetime,
        interface: str | None = None,
        subnet: str | None = None,
    ) -> tuple[Device, EventType | None]:
        """Record that ``mac`` was seen alive at ``seen_at``.

        ``interface`` and ``subnet`` (an IPv4 CIDR - ignored for an IPv6
        sighting) are discovery provenance for :meth:`mark_offline`'s
        offline-transition eligibility check; they are not reflected on
        :class:`Device` itself. Address family is inferred from ``ip``, not
        taken as a parameter, so a device's *known* IPv4/IPv6 coverage
        (``seen_via_ipv4``/``seen_via_ipv6``) only ever grows - it is never
        inferred solely from whichever address happens to be stored most
        recently, since IPv4 and IPv6 sightings of the same MAC overwrite
        the same ``ip`` column.

        Any positive sighting - even one older than the device's current
        ``last_seen`` (e.g. a delayed passive-queue entry) - is live proof
        the device isn't absent: it always resets the missed-sweep count to
        zero and widens known coverage. It only ever guards against moving
        ``last_seen``/``ip``/``hostname`` *backwards* in time.

        Returns the updated :class:`Device` and, if this observation is a
        lifecycle transition, the corresponding event type (``new_device`` the
        first time a MAC is ever seen, ``reappeared`` if it had been marked
        offline, or ``None`` for a routine still-online refresh).
        """

        existing = self.get_device(mac)
        event_type: EventType | None = None

        is_ipv4 = False
        is_ipv6 = False
        if ip:
            try:
                is_ipv4 = ipaddress.ip_address(ip).version == 4
                is_ipv6 = not is_ipv4
            except ValueError:
                pass
        ipv4_subnet = subnet if is_ipv4 else None

        if existing is None:
            event_type = "new_device"
            self._conn.execute(
                "INSERT INTO devices (mac, ip, hostname, vendor, status, first_seen, last_seen, "
                "missed_scans, seen_via_ipv4, seen_via_ipv6, last_interface, ipv4_subnet) "
                "VALUES (?, ?, ?, ?, 'online', ?, ?, 0, ?, ?, ?, ?)",
                (mac, ip, hostname, vendor, _iso(seen_at), _iso(seen_at),
                 int(is_ipv4), int(is_ipv6), interface, ipv4_subnet),
            )
        else:
            if existing.status == "offline":
                event_type = "reappeared"
            advance = seen_at >= existing.last_seen
            self._conn.execute(
                "UPDATE devices SET "
                "ip = CASE WHEN ? THEN ? ELSE ip END, "
                "hostname = CASE WHEN ? THEN ? ELSE hostname END, "
                "vendor = COALESCE(?, vendor), "
                "status = 'online', "
                "last_seen = CASE WHEN ? THEN ? ELSE last_seen END, "
                "missed_scans = 0, "
                "seen_via_ipv4 = seen_via_ipv4 OR ?, "
                "seen_via_ipv6 = seen_via_ipv6 OR ?, "
                "last_interface = COALESCE(?, last_interface), "
                "ipv4_subnet = COALESCE(?, ipv4_subnet) "
                "WHERE mac = ?",
                (
                    advance, ip,
                    advance, hostname,
                    vendor,
                    advance, _iso(seen_at),
                    int(is_ipv4), int(is_ipv6),
                    interface,
                    ipv4_subnet,
                    mac,
                ),
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
        self, mac: str, severity: Severity, *, now: datetime, cooldown_seconds: float, key: str | None = None
    ) -> bool:
        """Whether an external alert for ``mac`` at ``severity`` should fire now.

        Checks and records in one call, so a caller can't race between "may I
        alert" and "record that I did." Returns ``True`` - and upserts
        ``alert_log`` - when there is no prior record, the cooldown has
        elapsed since the last dispatch, or ``severity`` outranks what was
        last alerted (an escalation always bypasses the cooldown). Returns
        ``False`` without touching the row otherwise.
        ``cooldown_seconds <= 0`` always returns ``True`` (rate limiting off).

        ``key`` is the cooldown row's identity, defaulting to ``mac`` itself
        (every pre-existing caller's exact old behavior). Pass a distinct
        key to give some other notification for the same MAC its own,
        independent cooldown lane - e.g. an always-on availability
        *recovery* finding must never be swallowed just because that
        device's *absence* finding shares the same MAC and fired recently
        (see :func:`lanfence.engine.filter_rate_limited`). ``alert_log``'s
        ``mac`` column just stores whatever key it's given; no schema change
        needed for this.
        """

        if cooldown_seconds <= 0:
            return True
        key = key if key is not None else mac

        row = self._conn.execute(
            "SELECT last_alerted_at, last_severity FROM alert_log WHERE mac = ?", (key,)
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
            (key, _iso(now), severity),
        )
        self._conn.commit()
        return True

    def mark_offline(
        self,
        still_online_macs: set[str],
        *,
        as_of: datetime,
        grace_seconds: float = 0.0,
        missed_after: int = 1,
        ipv4_covered: bool = True,
        ipv4_subnet: str | None = None,
        ipv6_covered: bool = True,
        interface: str | None = None,
    ) -> list[DeviceEvent]:
        """Evaluate every currently-online device NOT in ``still_online_macs``
        for an offline transition; call this once per completed active-scan
        sweep.

        A device is only actually marked offline once BOTH: its consecutive
        *eligible* missed-sweep count reaches ``missed_after``, and the time
        elapsed since its ``last_seen`` reaches ``grace_seconds``. The
        defaults (0 seconds, 1 missed scan) reproduce the pre-grace-period
        behavior of disconnecting on the very first miss - callers that want
        the grace period pass ``cfg.scan.offline_grace_seconds``/
        ``offline_after_missed_scans`` explicitly (see
        :func:`lanfence.engine.run_active_sweep`).

        A "miss" only counts as eligible evidence of absence when this sweep
        actually covered the device's *known* discovery path(s):

        - A device with no recorded provenance at all (``seen_via_ipv4`` and
          ``seen_via_ipv6`` both false - e.g. a row from before this feature
          existed) is skipped entirely and conservatively: we don't know
          what this sweep did or didn't cover for it, so it is left alone
          until a fresh sighting establishes real coverage.
        - A device known via IPv4 only counts a miss when ``ipv4_covered``
          is true (the IPv4 sweep actually ran and succeeded, even if it
          found nothing - a successful empty scan is real evidence) AND, if
          both the device's recorded ``ipv4_subnet``/``interface`` and this
          sweep's are known, they match - a scan of a different subnet or
          interface says nothing about this device.
        - A device known via IPv6 only is the mirror of the above with
          ``ipv6_covered``/``interface``.
        - A device known via *both* requires both paths covered - any
          positive sighting (on either path) already keeps it online via
          :meth:`observe`, so reaching here at all means neither path saw it
          this sweep; conservatively, that only counts as absence if this
          sweep examined both of its known paths.

        Marking a device offline never advances ``last_seen`` - it stays the
        timestamp of the device's actual last sighting, not of the moment its
        absence was confirmed (that moment is the emitted event's own
        ``timestamp``).
        """

        events: list[DeviceEvent] = []
        rows = self._conn.execute(
            "SELECT mac, ip, hostname, last_seen, missed_scans, seen_via_ipv4, seen_via_ipv6, "
            "last_interface, ipv4_subnet FROM devices WHERE status = 'online'"
        ).fetchall()

        for row in rows:
            mac = row["mac"]
            if mac in still_online_macs:
                continue

            if not _path_covered(
                row, ipv4_covered=ipv4_covered, ipv4_subnet=ipv4_subnet,
                ipv6_covered=ipv6_covered, interface=interface,
            ):
                continue  # this sweep didn't examine (all of) this device's known paths

            missed = row["missed_scans"] + 1
            elapsed = (as_of - _parse_dt(row["last_seen"])).total_seconds()
            if missed >= missed_after and elapsed >= grace_seconds:
                self._conn.execute(
                    "UPDATE devices SET status = 'offline', missed_scans = 0 WHERE mac = ?", (mac,)
                )
                event = DeviceEvent(mac=mac, event_type="disconnected", timestamp=as_of,
                                     ip=row["ip"], hostname=row["hostname"])
                self.record_event(event)
                events.append(event)
            else:
                self._conn.execute("UPDATE devices SET missed_scans = ? WHERE mac = ?", (missed, mac))

        self._conn.commit()
        return events

    def evaluate_availability(
        self,
        *,
        as_of: datetime,
        default_offline_after_seconds: float,
        ipv4_covered: bool = True,
        ipv4_subnet: str | None = None,
        ipv6_covered: bool = True,
        interface: str | None = None,
    ) -> list[dict]:
        """Every currently-offline, ``always-on``, not-yet-alerted device
        whose absence has now reached its effective availability delay
        (its own ``--offline-after`` override, or ``default_offline_after_seconds``
        - normally ``cfg.scan.offline_grace_seconds`` - when unset).

        Call this once per eligible active sweep, alongside
        :meth:`mark_offline` - eligibility is gated by the same
        :func:`_path_covered` rule (reusing the existing conservative
        coverage rules: a failed, skipped, or out-of-scope sweep never
        creates an availability finding). This is a pure time check against
        an *already*-offline device, not a new miss - it does not touch
        ``missed_scans`` or emit a lifecycle event.

        Marks each returned device's episode ``availability_alerted`` before
        returning, atomically with the query, so a caller building and
        dispatching the actual :class:`~lanfence.models.Finding` can never
        double-fire even across a restart. Returns raw dicts (not
        :class:`Finding`) - building the human-facing finding text is
        :func:`lanfence.engine.evaluate_availability`'s job.
        """

        rows = self._conn.execute(
            "SELECT d.mac, d.ip, d.hostname, d.last_seen, d.seen_via_ipv4, d.seen_via_ipv6, "
            "d.last_interface, d.ipv4_subnet, p.offline_after_seconds "
            "FROM devices d JOIN device_presence p ON p.mac = d.mac "
            "WHERE d.status = 'offline' AND p.policy = 'always-on' AND p.availability_alerted = 0"
        ).fetchall()

        due: list[dict] = []
        for row in rows:
            if not _path_covered(
                row, ipv4_covered=ipv4_covered, ipv4_subnet=ipv4_subnet,
                ipv6_covered=ipv6_covered, interface=interface,
            ):
                continue
            effective = row["offline_after_seconds"] or default_offline_after_seconds
            elapsed = (as_of - _parse_dt(row["last_seen"])).total_seconds()
            if elapsed >= effective:
                due.append({
                    "mac": row["mac"], "ip": row["ip"], "hostname": row["hostname"],
                    "offline_after_seconds": effective,
                })

        for item in due:
            self.set_availability_alerted(item["mac"], True, updated_at=as_of)
        return due

    def reset_all(self) -> None:
        """Permanently delete every device, its lifecycle events, alert-
        dispatch cooldowns, review/snooze state, and presence policy - a
        full wipe back to an empty database. Used by ``lanfence reset``.
        Cannot be undone; trust (the allowlist) is separate and untouched by
        this call."""

        self._conn.execute("DELETE FROM devices")
        self._conn.execute("DELETE FROM events")
        self._conn.execute("DELETE FROM alert_log")
        self._conn.execute("DELETE FROM device_review")
        self._conn.execute("DELETE FROM device_presence")
        self._conn.commit()
