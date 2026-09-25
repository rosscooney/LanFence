# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Persistent SQLite store of every device LAN Fence has ever seen.

``devices`` holds the current state of each MAC address (first seen, last
seen, online/offline, and - for the offline-grace-period feature - its
consecutive-missed-scan count and discovery provenance); ``events`` is an
append-only log of lifecycle transitions (new / reappeared / disconnected)
used by ``lanfence report``; ``alert_log`` tracks the last external-alert
dispatch per cooldown key (usually a MAC, but see :meth:`due_for_alert`'s
``key`` param), used by :meth:`DeviceStore.due_for_alert` to cool down
repeated alerts for a flapping device or a noisy network-service finding;
``device_review`` tracks the ``lanfence review`` state (snoozed/
investigating) per MAC, used by ``lanfence devices``/``device``/``review``.
Trust itself is *not* stored here - it lives in the YAML allowlist (see
``lanfence/allowlist.py``); this table only tracks the review workflow
around a still-untrusted device. ``device_presence`` tracks per-device
presence policy (see :data:`lanfence.models.PresencePolicyName`).
``dhcp_servers``/``dhcp_server_findings`` track observed DHCP servers and
unexpected-server findings - see :mod:`lanfence.dhcp_server``.
``device_addresses``/``device_names`` retain *all* observed address/name
evidence for a MAC, each row keyed by (mac, ip/name_key, interface, source)
so a real dual-stack or multi-source observation is never overwritten by
another - see :class:`lanfence.models.AddressEvidence`/``NameEvidence`` and
:meth:`DeviceStore.preferred_address`/``preferred_name`` for how
``devices.ip``/``devices.hostname`` are computed from this evidence rather
than simply "whatever was written last". ``device_inspections`` holds the
*latest* explicit `lanfence inspect <mac>` result per MAC (see
:mod:`lanfence.active_inspect`) - never written by any passive/automatic
path.

``devices``' ``missed_scans``/``seen_via_ipv4``/``seen_via_ipv6``/
``last_interface``/``ipv4_subnet`` columns are provenance for
:meth:`DeviceStore.mark_offline` - see its docstring for how they gate an
offline transition. A row from before this feature existed has all of them
at their defaults (0/0/0/NULL/NULL), which reads as "no known coverage yet";
:meth:`mark_offline` treats that conservatively (never a miss) until a fresh
sighting establishes real provenance, rather than guessing.
"""

from __future__ import annotations

import errno
import ipaddress
import json
import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lanfence.models import (
    SEVERITIES,
    AddressEvidence,
    AdvertisedService,
    BaselineItem,
    ChangeEvent,
    Device,
    DeviceBaseline,
    DeviceEvent,
    DeviceMetadata,
    DhcpServerRecord,
    EventType,
    InspectedPort,
    InspectionResult,
    NameEvidence,
    PresenceState,
    ReviewState,
    RiskAssessment,
    RiskContribution,
    Severity,
)
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

CREATE TABLE IF NOT EXISTS dhcp_servers (
    interface TEXT NOT NULL,
    server_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    last_message_type TEXT,
    last_source_ip TEXT,
    last_source_mac TEXT,
    last_relay_ip TEXT,
    last_router TEXT,
    last_dns TEXT,
    PRIMARY KEY (interface, server_id)
);

CREATE TABLE IF NOT EXISTS dhcp_server_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface TEXT NOT NULL,
    server_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    approved_at_observation INTEGER NOT NULL,
    message_type TEXT,
    source_ip TEXT,
    source_mac TEXT,
    relay_ip TEXT,
    router TEXT,
    dns TEXT
);

CREATE INDEX IF NOT EXISTS idx_dhcp_server_findings_scope
    ON dhcp_server_findings (interface, server_id);

CREATE TABLE IF NOT EXISTS device_addresses (
    mac TEXT NOT NULL,
    ip TEXT NOT NULL,
    family TEXT NOT NULL,
    interface TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (mac, ip, interface, source)
);

CREATE INDEX IF NOT EXISTS idx_device_addresses_mac ON device_addresses (mac);

CREATE TABLE IF NOT EXISTS device_names (
    mac TEXT NOT NULL,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    source TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    interface TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (mac, name_key, source, ip, interface)
);

CREATE INDEX IF NOT EXISTS idx_device_names_mac ON device_names (mac);

CREATE TABLE IF NOT EXISTS device_metadata (
    mac TEXT PRIMARY KEY,
    owner TEXT,
    location TEXT,
    asset_type TEXT,
    purpose TEXT,
    notes TEXT,
    category_override TEXT,
    updated_at TEXT NOT NULL
);

-- mdns_ptr/srv/txt/addr: DNS names are case-insensitive identities (RFC
-- 1035/6762) - "Printer.local" and "printer.local" are the same name, so
-- the DNS-name-shaped key columns below use COLLATE NOCASE (ASCII-only
-- case folding, which is what SQLite's built-in NOCASE provides) so a
-- repeated observation with different letter case coalesces into the same
-- evidence row rather than creating a duplicate. This does not fold
-- non-ASCII text, which mostly affects DNS-SD *instance* labels (an
-- interoperability edge case, not the common "Printer.local" vs
-- "printer.local" case this guards against) - see _mdns_advertised_
-- services' own Python-side .lower() join for the cross-table PTR/SRV/A
-- correlation, which needs the same case-insensitivity independently of
-- SQL collation since it happens after rows are already fetched.
CREATE TABLE IF NOT EXISTS mdns_ptr (
    interface TEXT NOT NULL DEFAULT '',
    service_type TEXT NOT NULL COLLATE NOCASE,
    instance_name TEXT NOT NULL,
    fq_instance TEXT NOT NULL COLLATE NOCASE,
    ttl INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    withdrawn INTEGER NOT NULL DEFAULT 0,
    source_ip TEXT,
    source_mac TEXT,
    PRIMARY KEY (interface, service_type, fq_instance)
);

CREATE INDEX IF NOT EXISTS idx_mdns_ptr_fq_instance ON mdns_ptr (interface, fq_instance);

CREATE TABLE IF NOT EXISTS mdns_srv (
    interface TEXT NOT NULL DEFAULT '',
    fq_instance TEXT NOT NULL COLLATE NOCASE,
    target_host TEXT NOT NULL,
    port INTEGER NOT NULL,
    ttl INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    withdrawn INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (interface, fq_instance)
);

CREATE TABLE IF NOT EXISTS mdns_txt (
    interface TEXT NOT NULL DEFAULT '',
    fq_instance TEXT NOT NULL COLLATE NOCASE,
    attributes TEXT NOT NULL,
    ttl INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    withdrawn INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (interface, fq_instance)
);

CREATE TABLE IF NOT EXISTS mdns_addr (
    interface TEXT NOT NULL DEFAULT '',
    target_host TEXT NOT NULL COLLATE NOCASE,
    family TEXT NOT NULL,
    ip TEXT NOT NULL,
    ttl INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    withdrawn INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (interface, target_host, family, ip)
);

CREATE INDEX IF NOT EXISTS idx_mdns_addr_host ON mdns_addr (interface, target_host);
CREATE INDEX IF NOT EXISTS idx_mdns_addr_ip ON mdns_addr (ip);

CREATE TABLE IF NOT EXISTS ssdp_advertisements (
    interface TEXT NOT NULL DEFAULT '',
    usn TEXT NOT NULL,
    nt_or_st TEXT,
    server TEXT,
    location TEXT,
    max_age INTEGER,
    boot_id TEXT,
    config_id TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    withdrawn INTEGER NOT NULL DEFAULT 0,
    source_ip TEXT,
    source_mac TEXT,
    family TEXT,
    PRIMARY KEY (interface, usn)
);

CREATE INDEX IF NOT EXISTS idx_ssdp_source_ip ON ssdp_advertisements (source_ip);

-- A single-row fixed-window counter for the *global* alert-dispatch budget
-- (see DeviceStore.consume_global_alert_budget) - independent of the
-- per-MAC/per-subject cooldown in alert_log, so a flood of findings from
-- many rotating/spoofed identities (each individually "new" to alert_log)
-- still can't drive unbounded external alert volume.
CREATE TABLE IF NOT EXISTS alert_global_window (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    window_start TEXT NOT NULL,
    count INTEGER NOT NULL
);

-- Durable SMS-segment budget (see DeviceStore.consume_sms_budget), keyed by
-- a caller-chosen period (e.g. a UTC calendar day) so a restart never
-- resets how much of today's budget is already spent.
CREATE TABLE IF NOT EXISTS sms_budget (
    period_key TEXT PRIMARY KEY,
    segments_used INTEGER NOT NULL
);

-- One row per MAC (the *latest* run only - see DeviceStore.record_inspection)
-- from an explicit, operator-initiated `lanfence inspect <mac>`. Never
-- written by scan/monitor/passive discovery/review on their own.
CREATE TABLE IF NOT EXISTS device_inspections (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    open_ports TEXT NOT NULL,
    platform_guess TEXT,
    platform_confidence TEXT,
    platform_reasons TEXT NOT NULL
);

-- Know When It Changes (see lanfence/baseline.py). One row per structured
-- change - written only on a state transition, never per observation, and
-- bounded by DeviceStore's max_change_events / change retention.
CREATE TABLE IF NOT EXISTS change_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT,
    subject_id TEXT,
    change_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    signal TEXT,
    subject TEXT,
    previous TEXT NOT NULL DEFAULT '{}',
    current TEXT NOT NULL DEFAULT '{}',
    evidence TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL,
    significance TEXT NOT NULL,
    risk_before INTEGER,
    risk_after INTEGER,
    suppressed INTEGER NOT NULL DEFAULT 0,
    review_state TEXT NOT NULL DEFAULT 'unreviewed',
    review_note TEXT,
    reviewed_at TEXT,
    snoozed_until TEXT,
    policy_id TEXT,
    alerted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_change_events_time ON change_events (occurred_at);
CREATE INDEX IF NOT EXISTS idx_change_events_mac ON change_events (mac, occurred_at);

-- What's normal for each device: scalar observations here, set-valued
-- ones (ports, mDNS/SSDP service types, IPv6 prefixes) in baseline_items.
CREATE TABLE IF NOT EXISTS device_baselines (
    mac TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    established_at TEXT,
    excluded_signals TEXT NOT NULL DEFAULT '[]',
    ipv4 TEXT,
    hostname TEXT,
    identity_category TEXT,
    identity_manufacturer TEXT,
    trusted INTEGER NOT NULL DEFAULT 0,
    inspection_at TEXT,
    unknown_present_event_id INTEGER,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_items (
    mac TEXT NOT NULL,
    signal TEXT NOT NULL,
    value TEXT NOT NULL,
    in_baseline INTEGER NOT NULL,
    origin TEXT NOT NULL,
    present INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    removed_at TEXT,
    PRIMARY KEY (mac, signal, value)
);

-- The latest risk assessment per device only; its history is the
-- risk_changed rows in change_events, not a snapshot per sweep.
CREATE TABLE IF NOT EXISTS device_risk (
    mac TEXT PRIMARY KEY,
    score INTEGER NOT NULL,
    level TEXT NOT NULL,
    contributions TEXT NOT NULL,
    recommendation TEXT NOT NULL DEFAULT '',
    assessed_at TEXT NOT NULL
);

-- How far the change detector has read other append-only tables (events,
-- dhcp_server_findings), so each row becomes at most one change.
CREATE TABLE IF NOT EXISTS change_cursors (
    name TEXT PRIMARY KEY,
    position INTEGER NOT NULL
);
"""

#: Advertised-service evidence rows older than this, and already
#: expired/withdrawn, are opportunistically pruned on every discovery write
#: (see ``_prune_expired_discovery_evidence``) - bounded retention rather
#: than an unbounded history of every service ever glimpsed. A *current*
#: (not yet expired) advertisement is never pruned, regardless of age.
_DISCOVERY_RETENTION = timedelta(days=30)
_DISCOVERY_TABLES_WITH_EXPIRY = (
    "mdns_ptr", "mdns_srv", "mdns_txt", "mdns_addr", "ssdp_advertisements",
)

#: Default caps bounding how much a single attacker-controlled identity (a
#: spoofed/flapping MAC) or a burst of spoofed/rotating observations can
#: grow the database by - independent of (and tighter than) the time-based
#: retention above, which only prunes *expired* discovery rows. A caller
#: that has a :class:`lanfence.config.RetentionConfig` (``scan``/``monitor``)
#: passes its values into :class:`DeviceStore` explicitly; every other
#: caller (read-only commands, and any DeviceStore constructed without an
#: explicit override) gets these defaults - never unbounded.
_DEFAULT_MAX_EVIDENCE_ROWS_PER_MAC = 100
_DEFAULT_MAX_DHCP_SERVER_FINDINGS = 5000
_DEFAULT_MAX_DISCOVERY_ROWS_PER_TABLE = 5000
_DEFAULT_MAX_CHANGE_EVENTS = 20000
_DEFAULT_CHANGE_EVENT_RETENTION = timedelta(days=365)
#: Per-device cap on baseline items - a device advertising an endless
#: stream of distinct services can't grow the table without bound.
_MAX_BASELINE_ITEMS_PER_MAC = 200


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _is_usable_address(ip: str) -> bool:
    """Whether ``ip`` is worth recording as address evidence at all - never
    an unspecified address (``0.0.0.0``/``::``, e.g. a DAD probe or a
    not-yet-bound client), a multicast address, or IPv4's limited broadcast
    address. These are never a usable *device* address, regardless of which
    protocol produced the sighting."""

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if parsed.is_unspecified or parsed.is_multicast:
        return False
    if isinstance(parsed, ipaddress.IPv4Address) and str(parsed) == "255.255.255.255":
        return False
    return True


def _normalize_name_key(name: str) -> str:
    """The comparison key for a display name: lowercase, with exactly one
    trailing DNS root dot stripped (``"Printer.local."`` and
    ``"printer.local"`` are the same key; ``"printer"`` and
    ``"printer.local"`` are deliberately *not* - a short name is never
    treated as equivalent to a fully-qualified one just because it's a
    prefix)."""

    key = name.strip().lower()
    if key.endswith(".") and len(key) > 1:
        key = key[:-1]
    return key


#: Sentinel distinguishing "leave this field unchanged" from an explicit
#: ``None`` ("clear this field") in :meth:`DeviceStore.update_device_metadata`'s
#: tri-state keyword arguments.
_UNSET = object()


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
    # Know Your Network's ownership/asset fields (see DeviceMetadata) - an
    # existing device_metadata row keeps its owner/location untouched and
    # simply gets these new columns as NULL until the operator sets them.
    # (A friendly_name column from 0.6.1-0.6.2 may also exist; it's unused -
    # the allowlist's trusted name is the one device name.)
    "device_metadata": {
        "asset_type": "asset_type TEXT",
        "purpose": "purpose TEXT",
        "notes": "notes TEXT",
        "category_override": "category_override TEXT",
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


#: The device database and its containing directory hold every device
#: LAN Fence has ever seen (MACs, IPs, hostnames) - restricted to the
#: owning operator only, never group/world-readable, regardless of the
#: umask in effect when they're created. See :func:`_ensure_secure_directory`/
#: :func:`_open_or_create_database_file`.
_DB_DIR_MODE = 0o700
_DB_FILE_MODE = 0o600
#: SQLite creates these next to the main file depending on journal mode
#: (a transient rollback journal, or persistent -wal/-shm files once WAL
#: mode is used) - each must get the same restrictive permissions as the
#: main file whenever one exists. Best-effort: SQLite creates/removes them
#: internally during a transaction, outside this module's direct control,
#: so this is re-applied at DeviceStore construction time, not a
#: continuous guarantee - the containing directory's own 0700 mode (which
#: blocks every other user from even listing or traversing into it) is
#: the primary defense, this is defense in depth on top of it.
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


def _expected_owner_uid() -> int:
    """The uid LAN Fence's own state directory/database should be owned
    by. Normally the current process uid - but when running as root via
    ``sudo`` with a real ``SUDO_USER``, the *invoking operator's* uid,
    mirroring :func:`lanfence.config._operator_home`'s identical
    reasoning for ``~`` expansion: ``scan``/``monitor`` under `sudo`
    resolve ``db_path`` to the operator's own home directory (not
    ``/root``), so that directory is legitimately owned by the operator,
    not by root, even though this process's effective uid is 0. A
    genuine root login/system service (no ``SUDO_USER``) is left as uid 0.
    """

    if os.geteuid() != 0:
        return os.getuid()
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or sudo_user == "root":
        return 0
    try:
        import pwd

        return pwd.getpwnam(sudo_user).pw_uid
    except (KeyError, ImportError):
        return 0


def _check_fd_owner_and_mode(fd: int, path: Path, *, expected_uid: int, mode: int) -> None:
    """Verify an already-open fd's owner and tighten its mode *on the fd
    itself* (``os.fchmod``, never a second path-based ``os.chmod`` lookup
    that could itself race against a symlink swap at ``path``). Shared by
    the directory/file/sidecar helpers below."""

    st = os.fstat(fd)
    if st.st_uid != expected_uid:
        raise PermissionError(
            f"{path} is owned by uid {st.st_uid}, not the expected uid {expected_uid} "
            "- refusing to use a path this process does not own"
        )
    if stat.S_IMODE(st.st_mode) != mode:
        os.fchmod(fd, mode)


def _ensure_secure_directory(path: Path) -> None:
    """Ensure ``path`` - and only ``path``, never an ancestor - exists as
    a directory owned by :func:`_expected_owner_uid` and mode 0700.

    Missing ancestor directories (e.g. ``~/.local/share``, likely shared
    with other applications) are created with ordinary, umask-governed
    permissions if needed - never forced restrictive, and never
    re-chmod'd if they already exist; a legitimate symlinked *ancestor*
    (e.g. a platform alias, or an intentional bind-mount-style setup) is
    left completely alone. Only ``path`` itself (the directory LAN Fence
    actually owns and writes its database into) is ever opened/tightened,
    and only via ``O_NOFOLLOW`` - a single atomic syscall that refuses a
    symlink outright, never a separate ``exists()``/``is_symlink()``
    check followed by an ordinary open that a concurrent symlink swap
    could race between. Raises ``RuntimeError``/``PermissionError`` with
    a clear message - never silently proceeds - if ``path`` turns out to
    be a symlink, not a directory, owned by an unexpected uid, or its
    permissions can't be corrected.
    """

    if path.parent != path:
        path.parent.mkdir(parents=True, exist_ok=True)

    try:
        fd = os.open(str(path), os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        try:
            path.mkdir(mode=_DB_DIR_MODE)
        except FileExistsError:
            pass  # a concurrent same-user process created it first - fine, open it below
        try:
            fd = os.open(str(path), os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise PermissionError(f"could not create {path} securely: {exc}") from exc
    except OSError as exc:
        # A symlink at this exact path reads as ELOOP on some platforms
        # and ENOTDIR on others (macOS) when combined with O_DIRECTORY -
        # either way, it is not a real, direct directory and is refused.
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise RuntimeError(
                f"refusing to use {path}: it is a symlink (or not a real directory), not a plain directory"
            ) from exc
        raise PermissionError(f"could not open {path}: {exc}") from exc

    try:
        _check_fd_owner_and_mode(fd, path, expected_uid=_expected_owner_uid(), mode=_DB_DIR_MODE)
    except OSError as exc:
        if not isinstance(exc, PermissionError):
            raise PermissionError(f"could not restrict permissions on {path}: {exc}") from exc
        raise
    finally:
        os.close(fd)


def _open_nofollow_existing(path: Path, flags: int) -> int:
    """``open(2)`` with ``O_NOFOLLOW`` and no ``O_CREAT`` - a single
    atomic syscall that refuses (``ELOOP``) if the final path component is
    a symlink, rather than checking (``lstat``/``is_symlink``) and then
    opening as two separate operations with a race window between them."""

    try:
        return os.open(str(path), flags | os.O_NOFOLLOW)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise RuntimeError(f"refusing to use {path}: it is a symlink") from exc
        raise


def _open_or_create_database_file(path: Path, *, expected_uid: int) -> None:
    """Atomically open-or-create the main database file at ``path``
    without ever following a symlink there - two cases, each a single
    syscall:

    - Doesn't exist yet: ``O_CREAT | O_EXCL`` fails if *anything* is
      already there, including a dangling symlink - a pre-planted
      dangling symlink can never be "completed" by this call creating
      its target.
    - Already exists: :func:`_open_nofollow_existing` fails with a clear
      error if it's a symlink, guaranteeing this only ever proceeds with
      a real regular file.

    Either way, ownership/mode are verified and corrected on the fd
    itself before it's closed. `sqlite3.connect` is then given the plain
    path as usual (needed for SQLite's own journal/WAL sidecar-file name
    derivation, which requires a real path string, not an fd) - by that
    point the containing directory is already verified owner-only
    (:func:`_ensure_secure_directory`, mode 0700), so the residual window
    between this close and sqlite3's own open is only reachable by that
    same owning user (or root) - not a cross-user race.
    """

    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_RDWR, _DB_FILE_MODE)
    except FileExistsError:
        fd = _open_nofollow_existing(path, os.O_RDWR)

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError(f"refusing to use {path}: not a regular file")
        _check_fd_owner_and_mode(fd, path, expected_uid=expected_uid, mode=_DB_FILE_MODE)
    finally:
        os.close(fd)


def _secure_sqlite_sidecars(db_path: Path, *, expected_uid: int) -> None:
    """Best-effort permission/ownership check on any *already-existing*
    SQLite sidecar file (SQLite creates/removes these internally during a
    transaction, outside this module's control, so there is nothing to
    atomically "create" here the way :func:`_open_or_create_database_file`
    does for the main file) - opened via :func:`_open_nofollow_existing`,
    never a plain path-based check-then-chmod."""

    for suffix in _SQLITE_SIDECAR_SUFFIXES:
        sidecar = db_path.with_name(db_path.name + suffix)
        try:
            fd = _open_nofollow_existing(sidecar, os.O_RDWR)
        except FileNotFoundError:
            continue  # doesn't exist (the common case) - nothing to secure
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise RuntimeError(f"refusing to use {sidecar}: not a regular file")
            _check_fd_owner_and_mode(fd, sidecar, expected_uid=expected_uid, mode=_DB_FILE_MODE)
        finally:
            os.close(fd)


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
    def __init__(
        self,
        path: Path | str,
        *,
        max_evidence_rows_per_mac: int = _DEFAULT_MAX_EVIDENCE_ROWS_PER_MAC,
        max_dhcp_server_findings: int = _DEFAULT_MAX_DHCP_SERVER_FINDINGS,
        max_discovery_rows_per_table: int = _DEFAULT_MAX_DISCOVERY_ROWS_PER_TABLE,
        max_change_events: int = _DEFAULT_MAX_CHANGE_EVENTS,
        change_event_retention: timedelta = _DEFAULT_CHANGE_EVENT_RETENTION,
    ) -> None:
        self.path = Path(path)
        _ensure_secure_directory(self.path.parent)
        expected_uid = _expected_owner_uid()

        _open_or_create_database_file(self.path, expected_uid=expected_uid)
        _secure_sqlite_sidecars(self.path, expected_uid=expected_uid)

        self._max_evidence_rows_per_mac = max(1, max_evidence_rows_per_mac)
        self._max_dhcp_server_findings = max(1, max_dhcp_server_findings)
        self._max_discovery_rows_per_table = max(1, max_discovery_rows_per_table)
        self._max_change_events = max(1, max_change_events)
        self._change_event_retention = change_event_retention
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        for table, columns in _MIGRATED_COLUMNS.items():
            _ensure_columns(self._conn, table, columns)
        self._conn.commit()
        self._migrate_legacy_address_and_name_evidence()
        # The schema/migration steps above may have just created SQLite's
        # own journal/WAL sidecar files for the first time - secure those
        # too, not just whatever existed before this connection opened.
        _secure_sqlite_sidecars(self.path, expected_uid=expected_uid)

    def _enforce_row_cap(self, table: str, max_rows: int, *, order_by: str, mac: str | None = None) -> None:
        """Delete the oldest (by ``order_by``, descending) rows in ``table``
        beyond ``max_rows`` - bounded retention independent of the
        time-based expiry pruning elsewhere, so a burst of many distinct
        attacker-controlled rows (rotating identities, spoofed
        advertisements) can't grow this table without limit before any of
        them individually expire. ``table``/``order_by`` are always one of
        this module's own hardcoded literals, never caller/user input.
        """

        if mac is not None:
            self._conn.execute(
                f"DELETE FROM {table} WHERE mac = ? AND rowid NOT IN "
                f"(SELECT rowid FROM {table} WHERE mac = ? ORDER BY {order_by} DESC LIMIT ?)",
                (mac, mac, max_rows),
            )
        else:
            self._conn.execute(
                f"DELETE FROM {table} WHERE rowid NOT IN "
                f"(SELECT rowid FROM {table} ORDER BY {order_by} DESC LIMIT ?)",
                (max_rows,),
            )

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

    def device_counts(self) -> tuple[int, int]:
        """``(known, online)`` - a single aggregate query, never loading
        full device rows. Used by `lanfence monitor`'s live status footer,
        which needs these on a refresh cadence without the cost of
        ``all_devices()``/``online_devices()`` growing with inventory size.
        """

        row = self._conn.execute(
            "SELECT COUNT(*) AS known, SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS online "
            "FROM devices"
        ).fetchone()
        return int(row["known"] or 0), int(row["online"] or 0)

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

    #: Every column on ``device_metadata`` other than ``mac``/``updated_at``
    #: - drives :meth:`get_device_metadata`/``device_metadata_for_macs``/
    #: ``update_device_metadata`` so a new field is added in one place
    #: rather than four. Order matches the column order in ``_SCHEMA``.
    _METADATA_FIELDS: tuple[str, ...] = (
        "owner", "location", "asset_type", "purpose", "notes", "category_override",
    )

    def _row_to_metadata(self, mac: str, row: sqlite3.Row | None) -> DeviceMetadata:
        if row is None:
            return DeviceMetadata(mac=mac)
        values = {field_name: row[field_name] for field_name in self._METADATA_FIELDS}
        return DeviceMetadata(mac=mac, updated_at=_parse_dt(row["updated_at"]), **values)

    def get_device_metadata(self, mac: str) -> DeviceMetadata:
        """Operator-provided metadata for ``mac`` - every field ``None`` if
        never set. Separate from trust/review/presence and from observed
        hostname/vendor."""

        mac = normalize_mac(mac)
        columns = ", ".join(self._METADATA_FIELDS)
        row = self._conn.execute(
            f"SELECT {columns}, updated_at FROM device_metadata WHERE mac = ?",
            (mac,),
        ).fetchone()
        return self._row_to_metadata(mac, row)

    def device_metadata_for_macs(self, macs: list[str]) -> dict[str, DeviceMetadata]:
        """Metadata for several MACs in one query - used by
        :func:`lanfence.engine.build_inventory` so listing every device
        doesn't cost one query per row. MACs with no metadata row are
        simply absent from the result (the caller can default via
        :meth:`get_device_metadata`'s empty-row behavior)."""

        if not macs:
            return {}
        normalized = [normalize_mac(m) for m in macs]
        placeholders = ",".join("?" * len(normalized))
        columns = ", ".join(self._METADATA_FIELDS)
        rows = self._conn.execute(
            f"SELECT mac, {columns}, updated_at FROM device_metadata WHERE mac IN ({placeholders})",
            normalized,
        ).fetchall()
        return {row["mac"]: self._row_to_metadata(row["mac"], row) for row in rows}

    def update_device_metadata(
        self,
        mac: str,
        *,
        updated_at: datetime,
        owner: str | None | object = _UNSET,
        location: str | None | object = _UNSET,
        asset_type: str | None | object = _UNSET,
        purpose: str | None | object = _UNSET,
        notes: str | None | object = _UNSET,
        category_override: str | None | object = _UNSET,
    ) -> DeviceMetadata:
        """Apply any combination of metadata field changes atomically.

        Each field is tri-state: omitted (the ``_UNSET`` default) leaves it
        unchanged, ``None`` clears it, and a string sets it (already
        validated/sanitised by the caller - see ``lanfence device``'s CLI
        options and :mod:`lanfence.device_metadata`). Never creates a
        ``devices`` row - metadata can exist for a MAC with no observation
        history without implying one now exists. A no-op request (the
        merged result is identical to what's already stored) does not
        touch ``updated_at`` - see the class docs for why this matters for
        a durable "when did this last actually change" signal.
        """

        mac = normalize_mac(mac)
        current = self.get_device_metadata(mac)
        requested = {
            "owner": owner, "location": location, "asset_type": asset_type, "purpose": purpose, "notes": notes,
            "category_override": category_override,
        }
        merged = {
            field_name: getattr(current, field_name) if value is _UNSET else value
            for field_name, value in requested.items()
        }

        if all(merged[field_name] == getattr(current, field_name) for field_name in self._METADATA_FIELDS):
            return current

        columns = ", ".join(self._METADATA_FIELDS)
        placeholders = ", ".join("?" * len(self._METADATA_FIELDS))
        assignments = ", ".join(f"{field_name} = excluded.{field_name}" for field_name in self._METADATA_FIELDS)
        self._conn.execute(
            f"INSERT INTO device_metadata (mac, {columns}, updated_at) "
            f"VALUES (?, {placeholders}, ?) "
            f"ON CONFLICT(mac) DO UPDATE SET {assignments}, updated_at = excluded.updated_at",
            (mac, *(merged[field_name] for field_name in self._METADATA_FIELDS), _iso(updated_at)),
        )
        self._conn.commit()
        return self.get_device_metadata(mac)

    #: Priority tiers for computing a *preferred* address/name from retained
    #: evidence (lower wins) - see :meth:`refresh_preferred_fields`. A
    #: source missing here (shouldn't happen) sorts last.
    _ADDRESS_SOURCE_PRIORITY = {"arp": 0, "ipv6_nd": 0, "icmp": 0, "dhcp_ack": 1, "legacy_snapshot": 2}
    _NAME_SOURCE_PRIORITY = {"dhcp_option_12": 0, "reverse_dns": 1, "legacy_snapshot": 2}

    def record_address_evidence(
        self, mac: str, ip: str, *, interface: str, source: str, kind: str, seen_at: datetime,
    ) -> None:
        """Record one (mac, ip, interface, source) address observation,
        coalescing repeats into the same row (updating ``last_seen``, and
        widening ``first_seen`` backwards for a late-arriving older
        observation - never the other way for either bound) rather than
        inserting one row per packet. Silently does nothing for an address
        that's never usable device-address evidence (see
        :func:`_is_usable_address`) or that fails to parse. Does *not* by
        itself update ``devices.ip`` - see :meth:`refresh_preferred_fields`.
        """

        if not _is_usable_address(ip):
            return
        mac = normalize_mac(mac)
        try:
            family = "ipv4" if ipaddress.ip_address(ip).version == 4 else "ipv6"
        except ValueError:
            return
        interface = interface or ""

        existing = self._conn.execute(
            "SELECT first_seen, last_seen FROM device_addresses "
            "WHERE mac = ? AND ip = ? AND interface = ? AND source = ?",
            (mac, ip, interface, source),
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO device_addresses (mac, ip, family, interface, source, kind, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (mac, ip, family, interface, source, kind, _iso(seen_at), _iso(seen_at)),
            )
            self._enforce_row_cap(
                "device_addresses", self._max_evidence_rows_per_mac, order_by="last_seen", mac=mac,
            )
        else:
            new_first = min(_parse_dt(existing["first_seen"]), seen_at)
            new_last = max(_parse_dt(existing["last_seen"]), seen_at)
            self._conn.execute(
                "UPDATE device_addresses SET first_seen = ?, last_seen = ? "
                "WHERE mac = ? AND ip = ? AND interface = ? AND source = ?",
                (_iso(new_first), _iso(new_last), mac, ip, interface, source),
            )
        self._conn.commit()

    def record_name_evidence(
        self, mac: str, name: str, *, source: str, ip: str = "", interface: str = "", seen_at: datetime,
    ) -> None:
        """Record one (mac, name_key, source, ip, interface) name
        observation, coalescing repeats the same way as
        :meth:`record_address_evidence`. A falsy/whitespace-only ``name`` is
        silently skipped - a failed lookup must never erase or overwrite
        previously recorded name evidence, and this is how a caller
        expresses "nothing new to report" (simply don't call this)."""

        name = (name or "").strip()
        if not name:
            return
        mac = normalize_mac(mac)
        name_key = _normalize_name_key(name)
        ip = ip or ""
        interface = interface or ""

        existing = self._conn.execute(
            "SELECT first_seen, last_seen FROM device_names "
            "WHERE mac = ? AND name_key = ? AND source = ? AND ip = ? AND interface = ?",
            (mac, name_key, source, ip, interface),
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO device_names (mac, name, name_key, source, ip, interface, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (mac, name, name_key, source, ip, interface, _iso(seen_at), _iso(seen_at)),
            )
            self._enforce_row_cap(
                "device_names", self._max_evidence_rows_per_mac, order_by="last_seen", mac=mac,
            )
        else:
            new_first = min(_parse_dt(existing["first_seen"]), seen_at)
            new_last = max(_parse_dt(existing["last_seen"]), seen_at)
            self._conn.execute(
                "UPDATE device_names SET name = ?, first_seen = ?, last_seen = ? "
                "WHERE mac = ? AND name_key = ? AND source = ? AND ip = ? AND interface = ?",
                (name, _iso(new_first), _iso(new_last), mac, name_key, source, ip, interface),
            )
        self._conn.commit()

    def address_evidence_for(self, mac: str) -> list[AddressEvidence]:
        """Every retained address observation for ``mac``, most recently
        seen first. A pure database read."""

        mac = normalize_mac(mac)
        rows = self._conn.execute(
            "SELECT * FROM device_addresses WHERE mac = ? ORDER BY last_seen DESC", (mac,)
        ).fetchall()
        return [
            AddressEvidence(
                mac=mac, ip=row["ip"], family=row["family"], interface=row["interface"],
                source=row["source"], kind=row["kind"],
                first_seen=_parse_dt(row["first_seen"]), last_seen=_parse_dt(row["last_seen"]),
            )
            for row in rows
        ]

    def name_evidence_for(self, mac: str) -> list[NameEvidence]:
        """Every retained name observation for ``mac``, most recently seen
        first. A pure database read."""

        mac = normalize_mac(mac)
        rows = self._conn.execute(
            "SELECT * FROM device_names WHERE mac = ? ORDER BY last_seen DESC", (mac,)
        ).fetchall()
        return [
            NameEvidence(
                mac=mac, name=row["name"], name_key=row["name_key"], source=row["source"],
                ip=row["ip"], interface=row["interface"],
                first_seen=_parse_dt(row["first_seen"]), last_seen=_parse_dt(row["last_seen"]),
            )
            for row in rows
        ]

    def record_inspection(self, result: InspectionResult) -> None:
        """Persist ``result`` as the *latest* active-inspection run for its
        MAC - one row per device, replacing any earlier run rather than
        accumulating a history (see :class:`lanfence.models.InspectionResult`
        - a re-run is a deliberate refresh, and the whole point of storing
        ``observed_at`` is so a caller can judge how stale this one row is,
        not to keep old scans around)."""

        mac = normalize_mac(result.mac)
        self._conn.execute(
            "INSERT INTO device_inspections "
            "(mac, ip, method, observed_at, open_ports, platform_guess, platform_confidence, platform_reasons) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(mac) DO UPDATE SET "
            "ip = excluded.ip, method = excluded.method, observed_at = excluded.observed_at, "
            "open_ports = excluded.open_ports, platform_guess = excluded.platform_guess, "
            "platform_confidence = excluded.platform_confidence, platform_reasons = excluded.platform_reasons",
            (
                mac, result.ip, result.method, _iso(result.observed_at),
                json.dumps([p.model_dump(mode="json") for p in result.open_ports], separators=(",", ":")),
                result.platform_guess, result.platform_confidence,
                json.dumps(result.platform_reasons, separators=(",", ":")),
            ),
        )
        self._conn.commit()

    def inspection_for(self, mac: str) -> InspectionResult | None:
        """The most recent active-inspection result for ``mac``, or
        ``None`` if it has never been inspected. A pure database read -
        never triggers a new inspection (see :mod:`lanfence.active_inspect`
        for that)."""

        mac = normalize_mac(mac)
        row = self._conn.execute(
            "SELECT * FROM device_inspections WHERE mac = ?", (mac,)
        ).fetchone()
        if row is None:
            return None
        return InspectionResult(
            mac=mac, ip=row["ip"], method=row["method"], observed_at=_parse_dt(row["observed_at"]),
            open_ports=[InspectedPort(**p) for p in json.loads(row["open_ports"])],
            platform_guess=row["platform_guess"], platform_confidence=row["platform_confidence"],
            platform_reasons=json.loads(row["platform_reasons"]),
        )

    def preferred_address(self, mac: str) -> str | None:
        """The single best address for ``mac`` from retained evidence:
        directly-observed (arp/ipv6_nd) outranks a DHCP-reported lease,
        which outranks imported legacy data, regardless of recency: only
        *within* the same tier does the most recently observed win, and a
        further tie (identical timestamps) breaks on the IP string itself
        for a fully deterministic result. ``None`` if there is no evidence
        at all for this MAC yet."""

        mac = normalize_mac(mac)
        rows = self._conn.execute(
            "SELECT ip, source, last_seen FROM device_addresses WHERE mac = ?", (mac,)
        ).fetchall()
        if not rows:
            return None
        best = min(
            rows,
            key=lambda r: (
                self._ADDRESS_SOURCE_PRIORITY.get(r["source"], 99),
                -_parse_dt(r["last_seen"]).timestamp(),
                r["ip"],
            ),
        )
        return best["ip"]

    def preferred_addresses_by_family_for_macs(self, macs: list[str]) -> dict[str, dict[str, str | None]]:
        """For each of ``macs``, its preferred IPv4 and IPv6 address
        separately - :meth:`preferred_address`'s own priority rules
        (directly-observed outranks DHCP-reported outranks legacy, most
        recent wins within a tier), applied independently per address
        family, so a device with both an IPv4 and an IPv6 address can show
        both instead of just whichever family happens to win overall.

        One query for every MAC requested, mirroring
        :meth:`device_metadata_for_macs` - used by
        :func:`lanfence.engine.build_inventory` so listing every device
        doesn't cost two extra queries per row. A MAC with no evidence for
        a given family is simply absent from that family's slot (``None``).
        """

        if not macs:
            return {}
        normalized = [normalize_mac(m) for m in macs]
        placeholders = ",".join("?" * len(normalized))
        rows = self._conn.execute(
            f"SELECT mac, ip, family, source, last_seen FROM device_addresses WHERE mac IN ({placeholders})",
            normalized,
        ).fetchall()
        best: dict[tuple[str, str], tuple[tuple, str]] = {}
        for row in rows:
            key = (row["mac"], row["family"])
            candidate_rank = (
                self._ADDRESS_SOURCE_PRIORITY.get(row["source"], 99),
                -_parse_dt(row["last_seen"]).timestamp(),
                row["ip"],
            )
            current = best.get(key)
            if current is None or candidate_rank < current[0]:
                best[key] = (candidate_rank, row["ip"])
        result: dict[str, dict[str, str | None]] = {}
        for (mac, family), (_rank, ip) in best.items():
            result.setdefault(mac, {"ipv4": None, "ipv6": None})[family] = ip
        return result

    def preferred_name(self, mac: str) -> str | None:
        """The single best display name for ``mac`` from retained evidence:
        a nonempty DHCP-reported name outranks reverse DNS, which outranks
        imported legacy data; within a tier, most recent wins, with the
        name text itself as the final deterministic tie-breaker. ``None``
        if there is no name evidence at all for this MAC yet - a failed
        lookup never gets here, since :meth:`record_name_evidence` was
        never called for it in the first place."""

        mac = normalize_mac(mac)
        rows = self._conn.execute(
            "SELECT name, source, last_seen FROM device_names WHERE mac = ?", (mac,)
        ).fetchall()
        if not rows:
            return None
        best = min(
            rows,
            key=lambda r: (
                self._NAME_SOURCE_PRIORITY.get(r["source"], 99),
                -_parse_dt(r["last_seen"]).timestamp(),
                r["name"],
            ),
        )
        return best["name"]

    def refresh_preferred_fields(self, mac: str) -> None:
        """Recompute ``devices.ip``/``devices.hostname`` as the preferred
        value across all retained evidence (see :meth:`preferred_address`/
        ``preferred_name``) and write them through onto the ``devices`` row,
        so ordinary reads (``get_device``/``all_devices``) don't need to
        join evidence tables to show the correct value. When there is no
        evidence at all yet for this MAC, leaves the existing column value
        alone (``COALESCE``) rather than blanking it - this only matters for
        a MAC observed exclusively through an address-evidence-*excluded*
        path (e.g. only ever a bare DHCP client request - see ``observe``'s
        ``source`` parameter), where showing that best-effort raw value is
        more useful than showing nothing.
        """

        mac = normalize_mac(mac)
        preferred_ip = self.preferred_address(mac)
        preferred_name = self.preferred_name(mac)
        self._conn.execute(
            "UPDATE devices SET ip = COALESCE(?, ip), hostname = COALESCE(?, hostname) WHERE mac = ?",
            (preferred_ip, preferred_name, mac),
        )
        self._conn.commit()

    def _migrate_legacy_address_and_name_evidence(self) -> None:
        """One-time (per MAC), idempotent import of pre-existing
        ``devices.ip``/``devices.hostname`` values as ``legacy_snapshot``
        evidence, for any device that predates this feature.

        Guarded by "this MAC has no address/name evidence rows at all yet"
        rather than a separate migration-done flag - naturally idempotent
        (a MAC gains evidence the moment it's imported, or the moment a
        real observation arrives, so it's never reconsidered) and needs no
        extra schema. Uses *now* (the moment this snapshot was captured),
        not the device's own ``first_seen``, as both first_seen/last_seen
        for the imported evidence - it was not actually first observed at
        that IP/hostname back when the device itself first appeared, only
        confirmed to have it as of this migration.
        """

        now_dt = datetime.now(timezone.utc)
        now = _iso(now_dt)

        rows_missing_addresses = self._conn.execute(
            "SELECT mac, ip FROM devices WHERE ip IS NOT NULL AND ip != '' "
            "AND mac NOT IN (SELECT DISTINCT mac FROM device_addresses)"
        ).fetchall()
        for row in rows_missing_addresses:
            if not _is_usable_address(row["ip"]):
                continue
            try:
                family = "ipv4" if ipaddress.ip_address(row["ip"]).version == 4 else "ipv6"
            except ValueError:
                continue
            self._conn.execute(
                "INSERT INTO device_addresses (mac, ip, family, interface, source, kind, first_seen, last_seen) "
                "VALUES (?, ?, ?, '', 'legacy_snapshot', 'observed', ?, ?)",
                (row["mac"], row["ip"], family, now, now),
            )

        rows_missing_names = self._conn.execute(
            "SELECT mac, hostname FROM devices WHERE hostname IS NOT NULL AND hostname != '' "
            "AND mac NOT IN (SELECT DISTINCT mac FROM device_names)"
        ).fetchall()
        for row in rows_missing_names:
            name = row["hostname"].strip()
            if not name:
                continue
            self._conn.execute(
                "INSERT INTO device_names (mac, name, name_key, source, ip, interface, first_seen, last_seen) "
                "VALUES (?, ?, ?, 'legacy_snapshot', '', '', ?, ?)",
                (row["mac"], name, _normalize_name_key(name), now, now),
            )
        self._conn.commit()

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
        source: str = "arp",
        hostname_source: str | None = "reverse_dns",
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

        ``source``/``hostname_source`` (see :data:`lanfence.models.AddressSource`/
        ``NameSource``) additionally record durable address/name *evidence*
        (:meth:`record_address_evidence`/``record_name_evidence``) and
        recompute ``ip``/``hostname`` as the preferred value across all
        retained evidence (see :meth:`refresh_preferred_fields`) - a
        directly-observed address (``source="arp"``/``"ipv6_nd"``/``"icmp"``, the
        default) always wins over a merely-requested/offered one, so a
        caller with only a DHCP client request/offer to report (not yet a
        confirmed lease) should pass ``source="dhcp_client"``, which is
        deliberately *not* one of the address-evidence sources - the
        sighting still updates presence/coverage above, it just isn't
        trusted as address evidence. ``hostname_source=None`` records no
        name evidence for this call (the raw ``hostname`` value is still
        used for other purposes below) - contrast with omitting a hostname
        entirely (``hostname=None``), which is simply nothing to record.

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

        if ip and source in ("arp", "ipv6_nd", "icmp"):
            self.record_address_evidence(
                mac, ip, interface=interface or "", source=source, kind="observed", seen_at=seen_at,
            )
        if hostname and hostname_source:
            self.record_name_evidence(
                mac, hostname, source=hostname_source, ip=ip or "", interface=interface or "", seen_at=seen_at,
            )
        self.refresh_preferred_fields(mac)

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

    def consume_global_alert_budget(
        self, now: datetime, *, max_per_window: int, window_seconds: float,
    ) -> bool:
        """Whether one more external alert dispatch is allowed *right now*,
        under a global (not per-MAC/per-subject) fixed-window cap -
        independent of :meth:`due_for_alert`'s per-key cooldown, so a flood
        of findings from many rotating/spoofed identities (each
        individually "new" and therefore individually due) still can't
        drive unbounded total alert volume. Checks and records in one call.

        The window resets (to a fresh count of 1) once ``window_seconds``
        has elapsed since it started - this is a simple fixed window, not a
        sliding one, so it is not billed as a precise rate limiter, only a
        coarse volume cap. ``max_per_window <= 0`` or ``window_seconds <=
        0`` always returns ``True`` (disabled).
        """

        if max_per_window <= 0 or window_seconds <= 0:
            return True

        row = self._conn.execute(
            "SELECT window_start, count FROM alert_global_window WHERE id = 1"
        ).fetchone()
        if row is None or (now - _parse_dt(row["window_start"])).total_seconds() >= window_seconds:
            self._conn.execute(
                "INSERT INTO alert_global_window (id, window_start, count) VALUES (1, ?, 1) "
                "ON CONFLICT(id) DO UPDATE SET window_start = excluded.window_start, count = excluded.count",
                (_iso(now),),
            )
            self._conn.commit()
            return True

        if row["count"] >= max_per_window:
            return False

        self._conn.execute("UPDATE alert_global_window SET count = count + 1 WHERE id = 1")
        self._conn.commit()
        return True

    def consume_sms_budget(self, segments: int, *, now: datetime, max_segments_per_day: int) -> bool:
        """Atomically check-and-consume ``segments`` from the current UTC
        calendar day's durable SMS-segment budget. Returns ``True`` (and
        records the consumption) if enough budget remains; ``False``
        (no change made) otherwise - the caller is expected to skip sending
        that SMS rather than sending it anyway. Durable across restarts:
        this is a cost-safety guardrail, not a per-process counter, so
        restarting `lanfence monitor` (or any other command) never reopens
        today's budget - only the calendar day rolling over does.

        ``max_segments_per_day <= 0`` always returns ``True`` (unlimited).
        """

        if max_segments_per_day <= 0:
            return True
        period_key = now.astimezone(timezone.utc).strftime("%Y-%m-%d")

        row = self._conn.execute(
            "SELECT segments_used FROM sms_budget WHERE period_key = ?", (period_key,)
        ).fetchone()
        used = row["segments_used"] if row is not None else 0
        if used + segments > max_segments_per_day:
            return False

        if row is None:
            self._conn.execute(
                "INSERT INTO sms_budget (period_key, segments_used) VALUES (?, ?)", (period_key, segments),
            )
        else:
            self._conn.execute(
                "UPDATE sms_budget SET segments_used = segments_used + ? WHERE period_key = ?",
                (segments, period_key),
            )
        self._conn.commit()
        return True

    def devices_due_for_offline(
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
    ) -> list[Device]:
        """Every currently-online device that :meth:`mark_offline` would
        transition to offline right now, given the exact same arguments -
        read-only (never touches ``missed_scans``, never emits an event or
        commits anything), mirroring its per-row eligibility (see
        :func:`_path_covered`) and threshold (missed-scan count + grace
        period) check.

        For a caller that wants one last direct check before accepting an
        offline verdict - see :func:`lanfence.engine.run_active_sweep`,
        which probes each of these with :func:`lanfence.scanner.arp_probe`
        and folds an answering device back in as a real sighting instead
        of calling :meth:`mark_offline` on it. Keep this in sync with
        :meth:`mark_offline` if its eligibility/threshold logic ever
        changes.
        """

        rows = self._conn.execute(
            "SELECT mac, ip, hostname, last_seen, missed_scans, seen_via_ipv4, seen_via_ipv6, "
            "last_interface, ipv4_subnet FROM devices WHERE status = 'online'"
        ).fetchall()

        due: list[Device] = []
        for row in rows:
            mac = row["mac"]
            if mac in still_online_macs:
                continue
            if not _path_covered(
                row, ipv4_covered=ipv4_covered, ipv4_subnet=ipv4_subnet,
                ipv6_covered=ipv6_covered, interface=interface,
            ):
                continue
            missed = row["missed_scans"] + 1
            elapsed = (as_of - _parse_dt(row["last_seen"])).total_seconds()
            if missed >= missed_after and elapsed >= grace_seconds:
                device = self.get_device(mac)
                if device is not None:
                    due.append(device)
        return due

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
            "SELECT d.mac, d.ip, d.hostname, d.vendor, d.last_seen, d.seen_via_ipv4, d.seen_via_ipv6, "
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
                    "vendor": row["vendor"], "offline_after_seconds": effective,
                })

        for item in due:
            self.set_availability_alerted(item["mac"], True, updated_at=as_of)
        return due

    def reset_all(self) -> None:
        """Permanently delete every device, its lifecycle events, alert-
        dispatch cooldowns (per-device and global), review/snooze state,
        presence policy, observed DHCP servers/findings, retained
        address/name evidence, operator-provided metadata, and discovered
        advertised-service evidence - a full wipe back to an empty
        database. Used by ``lanfence reset``. Cannot be undone; trust (the
        allowlist) and DHCP server *approval* (config) are separate and
        untouched by this call. Metadata is always cleared here regardless
        of ``--keep-allowlist`` - that flag's documented scope is the
        allowlist file only, not device inventory data.

        Deliberately does **not** clear the durable SMS-segment budget
        (``sms_budget``) - that is a cost-safety guardrail, not device
        inventory, and resetting scanned history is not a way to reopen
        today's SMS spend cap."""

        self._conn.execute("DELETE FROM devices")
        self._conn.execute("DELETE FROM events")
        self._conn.execute("DELETE FROM alert_log")
        self._conn.execute("DELETE FROM alert_global_window")
        self._conn.execute("DELETE FROM device_review")
        self._conn.execute("DELETE FROM device_presence")
        self._conn.execute("DELETE FROM dhcp_servers")
        self._conn.execute("DELETE FROM dhcp_server_findings")
        self._conn.execute("DELETE FROM device_addresses")
        self._conn.execute("DELETE FROM device_names")
        self._conn.execute("DELETE FROM device_metadata")
        self._conn.execute("DELETE FROM device_inspections")
        for table in ("change_events", "device_baselines", "baseline_items", "device_risk", "change_cursors"):
            self._conn.execute(f"DELETE FROM {table}")
        for table in _DISCOVERY_TABLES_WITH_EXPIRY:
            self._conn.execute(f"DELETE FROM {table}")
        self._conn.commit()

    #: Per-device tables cleared by :meth:`delete_device` - the same
    #: per-MAC subset :meth:`reset_all` clears for every device, for
    #: exactly one. Deliberately excludes global-scope tables
    #: (``dhcp_servers``/``dhcp_server_findings``/``alert_global_window``/
    #: ``sms_budget``, none of which are owned by one device) and the
    #: mDNS/SSDP discovery-cache tables (only loosely associated with a
    #: device by hostname/IP match, not a hard foreign key - left to their
    #: own TTL-based expiry rather than risk deleting a shared record).
    _PER_DEVICE_TABLES = (
        "events", "alert_log", "device_review", "device_presence",
        "device_addresses", "device_names", "device_metadata", "device_inspections",
        "change_events", "device_baselines", "baseline_items", "device_risk",
    )

    def delete_device(self, mac: str) -> bool:
        """Permanently delete one device and its per-device data (see
        :data:`_PER_DEVICE_TABLES`) - the single-MAC equivalent of
        :meth:`reset_all`. Returns whether a ``devices`` row actually
        existed to delete (``False`` is not an error - deleting an
        already-gone MAC is a no-op). Cannot be undone. Never touches the
        allowlist - untrust separately first (``lanfence allow --remove``)
        if the device is currently trusted.
        """

        mac = normalize_mac(mac)
        cursor = self._conn.execute("DELETE FROM devices WHERE mac = ?", (mac,))
        existed = cursor.rowcount > 0
        for table in self._PER_DEVICE_TABLES:
            self._conn.execute(f"DELETE FROM {table} WHERE mac = ?", (mac,))
        self._conn.commit()
        return existed

    # --- DHCP server observations -------------------------------------

    def record_dhcp_server_observation(
        self,
        *,
        interface: str,
        server_id: str,
        message_type: str,
        observed_at: datetime,
        source_ip: str | None,
        source_mac: str | None,
        relay_ip: str | None,
        router: str | None,
        dns: str | None,
    ) -> None:
        """Coalesce one DHCPOFFER/ACK/NAK observation into the ``dhcp_servers``
        inventory - one row per (interface, server_id), not one row per
        packet. Updates ``last_*``/``last_seen`` and increments
        ``observation_count``; ``first_seen`` is set only the first time
        this (interface, server_id) pair is seen. Never writes a finding or
        touches cooldown state - see :mod:`lanfence.dhcp_server` for that.
        """

        existing = self._conn.execute(
            "SELECT first_seen FROM dhcp_servers WHERE interface = ? AND server_id = ?",
            (interface, server_id),
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO dhcp_servers (interface, server_id, first_seen, last_seen, "
                "observation_count, last_message_type, last_source_ip, last_source_mac, "
                "last_relay_ip, last_router, last_dns) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
                (interface, server_id, _iso(observed_at), _iso(observed_at),
                 message_type, source_ip, source_mac, relay_ip, router, dns),
            )
        else:
            self._conn.execute(
                "UPDATE dhcp_servers SET last_seen = ?, observation_count = observation_count + 1, "
                "last_message_type = ?, last_source_ip = ?, last_source_mac = ?, last_relay_ip = ?, "
                "last_router = ?, last_dns = ? WHERE interface = ? AND server_id = ?",
                (_iso(observed_at), message_type, source_ip, source_mac, relay_ip, router, dns,
                 interface, server_id),
            )
        self._conn.commit()

    def dhcp_server_records(self) -> list[DhcpServerRecord]:
        """Every observed DHCP server, coalesced - a pure database read.
        ``approved``/``name`` are left at their defaults here; the caller
        (see :mod:`lanfence.dhcp_server`) joins in current config, since
        approval is a config fact, not something this store knows about."""

        rows = self._conn.execute(
            "SELECT * FROM dhcp_servers ORDER BY interface ASC, server_id ASC"
        ).fetchall()
        return [
            DhcpServerRecord(
                interface=row["interface"],
                server_id=row["server_id"],
                first_seen=_parse_dt(row["first_seen"]),
                last_seen=_parse_dt(row["last_seen"]),
                observation_count=row["observation_count"],
                last_message_type=row["last_message_type"],
                last_source_ip=row["last_source_ip"],
                last_source_mac=row["last_source_mac"],
                last_relay_ip=row["last_relay_ip"],
                last_router=row["last_router"],
                last_dns=row["last_dns"],
            )
            for row in rows
        ]

    def record_dhcp_server_finding(
        self,
        *,
        interface: str,
        server_id: str,
        observed_at: datetime,
        approved_at_observation: bool,
        message_type: str | None,
        source_ip: str | None,
        source_mac: str | None,
        relay_ip: str | None,
        router: str | None,
        dns: str | None,
    ) -> None:
        """Durably record one unexpected-DHCP-server finding's original
        evidence and approval status *at the time it was observed* - a
        later config change approving this server must never rewrite this
        history (see the module docstring's persistence requirements)."""

        self._conn.execute(
            "INSERT INTO dhcp_server_findings (interface, server_id, observed_at, "
            "approved_at_observation, message_type, source_ip, source_mac, relay_ip, router, dns) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (interface, server_id, _iso(observed_at), int(approved_at_observation),
             message_type, source_ip, source_mac, relay_ip, router, dns),
        )
        self._enforce_row_cap("dhcp_server_findings", self._max_dhcp_server_findings, order_by="id")
        self._conn.commit()

    # --- passive advertised-service discovery (mDNS/DNS-SD, SSDP/UPnP) -

    def _prune_expired_discovery_evidence(self, *, as_of: datetime) -> None:
        """Bounded retention: an expired or explicitly withdrawn discovery
        record older than :data:`_DISCOVERY_RETENTION` is opportunistically
        deleted on every discovery write, rather than an unbounded history
        of every service ever glimpsed. A *current* (not yet expired)
        record is never pruned here, regardless of age. The caller must commit
        after pruning: even a DELETE matching no rows opens a write
        transaction and otherwise leaves an idle monitor holding the lock."""

        cutoff = _iso(as_of - _DISCOVERY_RETENTION)
        now_iso = _iso(as_of)
        for table in _DISCOVERY_TABLES_WITH_EXPIRY:
            self._conn.execute(
                f"DELETE FROM {table} WHERE last_seen < ? AND "
                "(withdrawn = 1 OR (expires_at IS NOT NULL AND expires_at < ?))",
                (cutoff, now_iso),
            )
            # A count-based cap independent of the time-based expiry above:
            # a burst of many distinct, still-unexpired fake advertisements
            # (rotating identifiers) would otherwise grow this table without
            # limit until each one's own TTL naturally elapses.
            self._enforce_row_cap(table, self._max_discovery_rows_per_table, order_by="last_seen")

    def discovery_diagnostics(self) -> dict[str, int]:
        """Row counts per discovery table - bounded capacity visibility for
        troubleshooting (see :data:`_DISCOVERY_RETENTION`)."""

        return {
            table: self._conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
            for table in _DISCOVERY_TABLES_WITH_EXPIRY
        }

    def record_mdns_ptr(
        self, *, interface: str, service_type: str, instance_name: str, fq_instance: str,
        ttl: int, seen_at: datetime, source_ip: str | None, source_mac: str | None,
    ) -> None:
        """Upsert one PTR (service-type -> instance) observation - see
        :class:`lanfence.discovery.MdnsRecordSighting`. Repeated
        announcements of the same (interface, service_type, fq_instance)
        update evidence in place rather than accumulating one row per
        packet; a late-arriving older observation widens ``first_seen``
        backwards, never the reverse (mirrors
        :meth:`record_address_evidence`)."""

        interface = interface or ""
        expires_at = seen_at + timedelta(seconds=ttl)
        existing = self._conn.execute(
            "SELECT first_seen FROM mdns_ptr WHERE interface = ? AND service_type = ? AND fq_instance = ?",
            (interface, service_type, fq_instance),
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO mdns_ptr (interface, service_type, instance_name, fq_instance, ttl, "
                "first_seen, last_seen, expires_at, withdrawn, source_ip, source_mac) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
                (interface, service_type, instance_name, fq_instance, ttl,
                 _iso(seen_at), _iso(seen_at), _iso(expires_at), source_ip, source_mac),
            )
        else:
            first_seen = min(_parse_dt(existing["first_seen"]), seen_at)
            self._conn.execute(
                "UPDATE mdns_ptr SET instance_name = ?, ttl = ?, first_seen = ?, last_seen = ?, "
                "expires_at = ?, withdrawn = 0, source_ip = ?, source_mac = ? "
                "WHERE interface = ? AND service_type = ? AND fq_instance = ?",
                (instance_name, ttl, _iso(first_seen), _iso(seen_at), _iso(expires_at), source_ip, source_mac,
                 interface, service_type, fq_instance),
            )
        self._prune_expired_discovery_evidence(as_of=seen_at)
        self._conn.commit()

    def withdraw_mdns_ptr(self, interface: str, service_type: str, fq_instance: str) -> None:
        """RFC 6762 s10.1 "goodbye" (TTL 0): withdraw a matching PTR if one
        exists; a no-op for one never seen - never fabricates a fresh
        entry just to mark it withdrawn."""

        self._conn.execute(
            "UPDATE mdns_ptr SET withdrawn = 1 WHERE interface = ? AND service_type = ? AND fq_instance = ?",
            (interface or "", service_type, fq_instance),
        )
        self._conn.commit()

    def record_mdns_srv(
        self, *, interface: str, fq_instance: str, target_host: str, port: int, ttl: int, seen_at: datetime,
    ) -> None:
        """Upsert one SRV (instance -> target host/port) observation. Its
        own TTL/expiry is tracked independently of the owning PTR's - a
        refreshed PTR never extends an expired SRV, and vice versa."""

        interface = interface or ""
        expires_at = seen_at + timedelta(seconds=ttl)
        existing = self._conn.execute(
            "SELECT first_seen FROM mdns_srv WHERE interface = ? AND fq_instance = ?",
            (interface, fq_instance),
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO mdns_srv (interface, fq_instance, target_host, port, ttl, "
                "first_seen, last_seen, expires_at, withdrawn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (interface, fq_instance, target_host, port, ttl, _iso(seen_at), _iso(seen_at), _iso(expires_at)),
            )
        else:
            first_seen = min(_parse_dt(existing["first_seen"]), seen_at)
            self._conn.execute(
                "UPDATE mdns_srv SET target_host = ?, port = ?, ttl = ?, first_seen = ?, last_seen = ?, "
                "expires_at = ?, withdrawn = 0 WHERE interface = ? AND fq_instance = ?",
                (target_host, port, ttl, _iso(first_seen), _iso(seen_at), _iso(expires_at), interface, fq_instance),
            )
        self._prune_expired_discovery_evidence(as_of=seen_at)
        self._conn.commit()

    def withdraw_mdns_srv(self, interface: str, fq_instance: str) -> None:
        self._conn.execute(
            "UPDATE mdns_srv SET withdrawn = 1 WHERE interface = ? AND fq_instance = ?",
            (interface or "", fq_instance),
        )
        self._conn.commit()

    def record_mdns_txt(
        self, *, interface: str, fq_instance: str, attributes: dict[str, str], ttl: int, seen_at: datetime,
    ) -> None:
        """Upsert one TXT observation - ``attributes`` must already be the
        small, bounded, allowlisted set (see
        :func:`lanfence.discovery._parse_txt_rdata`); this method stores
        exactly what it's given and never retains a raw TXT blob."""

        interface = interface or ""
        expires_at = seen_at + timedelta(seconds=ttl)
        payload = json.dumps(attributes, separators=(",", ":"), sort_keys=True)
        existing = self._conn.execute(
            "SELECT first_seen FROM mdns_txt WHERE interface = ? AND fq_instance = ?",
            (interface, fq_instance),
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO mdns_txt (interface, fq_instance, attributes, ttl, first_seen, last_seen, "
                "expires_at, withdrawn) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (interface, fq_instance, payload, ttl, _iso(seen_at), _iso(seen_at), _iso(expires_at)),
            )
        else:
            first_seen = min(_parse_dt(existing["first_seen"]), seen_at)
            self._conn.execute(
                "UPDATE mdns_txt SET attributes = ?, ttl = ?, first_seen = ?, last_seen = ?, expires_at = ?, "
                "withdrawn = 0 WHERE interface = ? AND fq_instance = ?",
                (payload, ttl, _iso(first_seen), _iso(seen_at), _iso(expires_at), interface, fq_instance),
            )
        self._prune_expired_discovery_evidence(as_of=seen_at)
        self._conn.commit()

    def withdraw_mdns_txt(self, interface: str, fq_instance: str) -> None:
        self._conn.execute(
            "UPDATE mdns_txt SET withdrawn = 1 WHERE interface = ? AND fq_instance = ?",
            (interface or "", fq_instance),
        )
        self._conn.commit()

    def record_mdns_addr(
        self, *, interface: str, target_host: str, family: str, ip: str, ttl: int, seen_at: datetime,
        cache_flush: bool = False,
    ) -> None:
        """Upsert one A/AAAA (target host -> address) observation.

        ``cache_flush`` implements RFC 6762 s10.2's grace behavior: a
        cache-flush record asserts the responder now holds the complete
        RRset for (target_host, family), so any *other* address under the
        same (interface, target_host, family) - a genuinely related
        record, never an unrelated name/type - is marked withdrawn, but
        only once at least one second has passed since it was last seen
        (the grace window RFC 6762 describes, so records arriving in the
        same multi-packet response are never mistakenly flushed).
        """

        interface = interface or ""
        expires_at = seen_at + timedelta(seconds=ttl)
        existing = self._conn.execute(
            "SELECT first_seen FROM mdns_addr WHERE interface = ? AND target_host = ? AND family = ? AND ip = ?",
            (interface, target_host, family, ip),
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO mdns_addr (interface, target_host, family, ip, ttl, first_seen, last_seen, "
                "expires_at, withdrawn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (interface, target_host, family, ip, ttl, _iso(seen_at), _iso(seen_at), _iso(expires_at)),
            )
        else:
            first_seen = min(_parse_dt(existing["first_seen"]), seen_at)
            self._conn.execute(
                "UPDATE mdns_addr SET ttl = ?, first_seen = ?, last_seen = ?, expires_at = ?, withdrawn = 0 "
                "WHERE interface = ? AND target_host = ? AND family = ? AND ip = ?",
                (ttl, _iso(first_seen), _iso(seen_at), _iso(expires_at), interface, target_host, family, ip),
            )
        if cache_flush:
            grace_cutoff = _iso(seen_at - timedelta(seconds=1))
            self._conn.execute(
                "UPDATE mdns_addr SET withdrawn = 1 WHERE interface = ? AND target_host = ? AND family = ? "
                "AND ip != ? AND withdrawn = 0 AND last_seen < ?",
                (interface, target_host, family, ip, grace_cutoff),
            )
        self._prune_expired_discovery_evidence(as_of=seen_at)
        self._conn.commit()

    def withdraw_mdns_addr(self, interface: str, target_host: str, family: str, ip: str) -> None:
        self._conn.execute(
            "UPDATE mdns_addr SET withdrawn = 1 WHERE interface = ? AND target_host = ? AND family = ? AND ip = ?",
            (interface or "", target_host, family, ip),
        )
        self._conn.commit()

    def record_ssdp_advertisement(
        self, *, interface: str, usn: str, nt_or_st: str | None, server: str | None, location: str | None,
        max_age: int | None, boot_id: str | None, config_id: str | None, seen_at: datetime,
        source_ip: str | None, source_mac: str | None, family: str | None,
    ) -> None:
        """Upsert one SSDP alive/update/response observation, keyed by the
        stable (interface, USN) identity - never the transient NOTIFY
        content alone. ``location`` is stored as untrusted advertised
        metadata only; it is never fetched (see :mod:`lanfence.discovery`).
        """

        interface = interface or ""
        expires_at = seen_at + timedelta(seconds=max_age) if max_age else None
        existing = self._conn.execute(
            "SELECT first_seen FROM ssdp_advertisements WHERE interface = ? AND usn = ?",
            (interface, usn),
        ).fetchone()
        expires_iso = _iso(expires_at) if expires_at else None
        if existing is None:
            self._conn.execute(
                "INSERT INTO ssdp_advertisements (interface, usn, nt_or_st, server, location, max_age, "
                "boot_id, config_id, first_seen, last_seen, expires_at, withdrawn, source_ip, source_mac, family) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
                (interface, usn, nt_or_st, server, location, max_age, boot_id, config_id,
                 _iso(seen_at), _iso(seen_at), expires_iso, source_ip, source_mac, family),
            )
        else:
            first_seen = min(_parse_dt(existing["first_seen"]), seen_at)
            self._conn.execute(
                "UPDATE ssdp_advertisements SET nt_or_st = ?, server = ?, location = ?, max_age = ?, "
                "boot_id = ?, config_id = ?, first_seen = ?, last_seen = ?, expires_at = ?, withdrawn = 0, "
                "source_ip = ?, source_mac = ?, family = ? WHERE interface = ? AND usn = ?",
                (nt_or_st, server, location, max_age, boot_id, config_id, _iso(first_seen), _iso(seen_at),
                 expires_iso, source_ip, source_mac, family, interface, usn),
            )
        self._prune_expired_discovery_evidence(as_of=seen_at)
        self._conn.commit()

    def withdraw_ssdp_advertisement(self, interface: str, usn: str, *, seen_at: datetime) -> None:
        """``ssdp:byebye`` withdraws only the matching (interface, USN)
        advertisement, never every service the device advertises - a
        device sends one byebye per USN it's withdrawing, each
        independently keyed. A no-op for a USN never seen."""

        self._conn.execute(
            "UPDATE ssdp_advertisements SET withdrawn = 1, last_seen = ? WHERE interface = ? AND usn = ?",
            (_iso(seen_at), interface or "", usn),
        )
        self._conn.commit()

    def _directly_observed_mac_for_ip(self, ip: str) -> str | None:
        """The single MAC directly observed (ARP/IPv6 ND/ping - never a DHCP
        lease claim or imported legacy data) holding ``ip`` as address
        evidence, or ``None`` if zero or more than one distinct MAC has
        ever held it. An ambiguous or merely historical IP-to-MAC
        association must never produce a confident attribution - see
        :meth:`advertised_services`."""

        rows = self._conn.execute(
            "SELECT DISTINCT mac FROM device_addresses WHERE ip = ? AND source IN ('arp', 'ipv6_nd', 'icmp')",
            (ip,),
        ).fetchall()
        macs = {row["mac"] for row in rows}
        return next(iter(macs)) if len(macs) == 1 else None

    @staticmethod
    def _discovery_status(row: sqlite3.Row, *, now: datetime) -> str:
        if row["withdrawn"]:
            return "withdrawn"
        expires_at = row["expires_at"]
        if expires_at and _parse_dt(expires_at) < now:
            return "expired"
        return "current"

    def _mdns_advertised_services(self, *, now: datetime) -> list[AdvertisedService]:
        from lanfence.discovery import well_known_mdns_label

        # DNS names are case-insensitive identities (RFC 1035/6762) - keys
        # here are lower-cased ASCII-foldable joins so "Printer.local" and
        # "printer.local" correlate as the same name regardless of which
        # case any one record happened to use (SQL-level COLLATE NOCASE on
        # the schema's own key columns handles per-table dedup; this join
        # happens in Python after fetch, so it needs its own folding).
        ptr_rows = self._conn.execute("SELECT * FROM mdns_ptr").fetchall()
        srv_by_key = {
            (row["interface"], row["fq_instance"].lower()): row
            for row in self._conn.execute("SELECT * FROM mdns_srv").fetchall()
        }
        txt_by_key = {
            (row["interface"], row["fq_instance"].lower()): row
            for row in self._conn.execute("SELECT * FROM mdns_txt").fetchall()
        }
        addrs_by_host: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for row in self._conn.execute("SELECT * FROM mdns_addr").fetchall():
            addrs_by_host.setdefault((row["interface"], row["target_host"].lower()), []).append(row)

        results: list[AdvertisedService] = []
        for ptr in ptr_rows:
            key = (ptr["interface"], ptr["fq_instance"].lower())
            srv = srv_by_key.get(key)
            txt = txt_by_key.get(key)

            target_host = srv["target_host"] if srv else None
            target_port = srv["port"] if srv else None
            addresses: list[str] = []
            candidate_macs: set[str] = set()
            if target_host:
                for addr_row in addrs_by_host.get((ptr["interface"], target_host.lower()), []):
                    if addr_row["withdrawn"]:
                        continue
                    addresses.append(addr_row["ip"])
                    found_mac = self._directly_observed_mac_for_ip(addr_row["ip"])
                    if found_mac:
                        candidate_macs.add(found_mac)
            mac = next(iter(candidate_macs)) if len(candidate_macs) == 1 else None

            attributes: dict[str, str] = {}
            if txt is not None:
                try:
                    attributes = json.loads(txt["attributes"])
                except (TypeError, ValueError):
                    attributes = {}

            results.append(
                AdvertisedService(
                    protocol="mdns",
                    interface=ptr["interface"],
                    service_type=ptr["service_type"],
                    service_label=well_known_mdns_label(ptr["service_type"]),
                    instance_name=ptr["instance_name"],
                    identity=ptr["fq_instance"],
                    target_host=target_host,
                    target_port=target_port,
                    addresses=addresses,
                    mac=mac,
                    attribution_basis="target_address_match" if mac else None,
                    attributes=attributes,
                    first_seen=_parse_dt(ptr["first_seen"]),
                    last_seen=_parse_dt(ptr["last_seen"]),
                    expires_at=_parse_dt(ptr["expires_at"]) if ptr["expires_at"] else None,
                    status=self._discovery_status(ptr, now=now),
                )
            )
        return results

    def _ssdp_advertised_services(self, *, now: datetime) -> list[AdvertisedService]:
        rows = self._conn.execute("SELECT * FROM ssdp_advertisements").fetchall()
        results: list[AdvertisedService] = []
        for row in rows:
            mac = self._directly_observed_mac_for_ip(row["source_ip"]) if row["source_ip"] else None
            results.append(
                AdvertisedService(
                    protocol="ssdp",
                    interface=row["interface"],
                    family=row["family"],
                    service_type=row["nt_or_st"] or "",
                    identity=row["usn"],
                    server=row["server"],
                    location=row["location"],
                    mac=mac,
                    attribution_basis="source_address_match" if mac else None,
                    first_seen=_parse_dt(row["first_seen"]),
                    last_seen=_parse_dt(row["last_seen"]),
                    expires_at=_parse_dt(row["expires_at"]) if row["expires_at"] else None,
                    status=self._discovery_status(row, now=now),
                )
            )
        return results

    def advertised_services(
        self, *, mac: str | None = None, protocol: str | None = None,
        include_expired: bool = False, unassociated_only: bool = False,
        now: datetime | None = None,
    ) -> list[AdvertisedService]:
        """Every known advertised service (mDNS/DNS-SD or SSDP/UPnP),
        correlated from the bounded evidence tables - a pure database read;
        never scans, never sends discovery traffic.

        Attribution (``mac``/``attribution_basis``) is computed fresh on
        every call from *current* directly-observed address evidence (see
        :meth:`_directly_observed_mac_for_ip`) - the transmitting frame's
        own Ethernet/IP source is deliberately never trusted by itself (an
        mDNS proxy/reflector or a shared responder can advertise services
        on behalf of other hosts), and an ambiguous or merely historical
        IP-to-MAC association leaves a service unassociated rather than
        guessing. This also means attribution can only be *reevaluated* as
        better evidence arrives - the underlying advertisement rows
        themselves are never rewritten to reflect it.

        ``include_expired=False`` (the default) returns only
        ``"current"`` advertisements; ``True`` also includes
        ``"expired"``/``"withdrawn"`` history, each explicitly labeled via
        ``status``. Filters combine with AND.
        """

        now = now or datetime.now(timezone.utc)
        services: list[AdvertisedService] = []
        if protocol in (None, "mdns"):
            services.extend(self._mdns_advertised_services(now=now))
        if protocol in (None, "ssdp"):
            services.extend(self._ssdp_advertised_services(now=now))

        if not include_expired:
            services = [s for s in services if s.status == "current"]
        if mac is not None:
            mac_norm = normalize_mac(mac)
            services = [s for s in services if s.mac == mac_norm]
        if unassociated_only:
            services = [s for s in services if s.mac is None]
        services.sort(key=lambda s: (s.protocol, s.service_type, s.identity))
        return services

    # --- Know When It Changes: change events --------------------------

    def record_change_event(self, event: ChangeEvent) -> ChangeEvent:
        """Store one change and return it with its ``id``. Then applies
        retention (row cap and age) so the table stays bounded."""

        cursor = self._conn.execute(
            "INSERT INTO change_events (mac, subject_id, change_type, occurred_at, signal, subject, previous, "
            "current, evidence, source, significance, risk_before, risk_after, suppressed, review_state, "
            "review_note, reviewed_at, snoozed_until, policy_id, alerted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.mac, event.subject_id, event.change_type, _iso(event.occurred_at), event.signal,
                event.subject, json.dumps(event.previous, separators=(",", ":")),
                json.dumps(event.current, separators=(",", ":")),
                json.dumps(event.evidence, separators=(",", ":")), event.source, event.significance,
                event.risk_before, event.risk_after, int(event.suppressed), event.review_state,
                event.review_note, _iso(event.reviewed_at) if event.reviewed_at else None,
                _iso(event.snoozed_until) if event.snoozed_until else None, event.policy_id,
                _iso(event.alerted_at) if event.alerted_at else None,
            ),
        )
        self._conn.execute(
            "DELETE FROM change_events WHERE occurred_at < ?",
            (_iso(event.occurred_at - self._change_event_retention),),
        )
        self._enforce_row_cap("change_events", self._max_change_events, order_by="id")
        self._conn.commit()
        return event.model_copy(update={"id": cursor.lastrowid})

    @staticmethod
    def _row_to_change_event(row: sqlite3.Row) -> ChangeEvent:
        def _dt(value: str | None) -> datetime | None:
            return _parse_dt(value) if value else None

        return ChangeEvent(
            id=row["id"], mac=row["mac"], subject_id=row["subject_id"], change_type=row["change_type"],
            occurred_at=_parse_dt(row["occurred_at"]), signal=row["signal"], subject=row["subject"],
            previous=json.loads(row["previous"]), current=json.loads(row["current"]),
            evidence=json.loads(row["evidence"]), source=row["source"], significance=row["significance"],
            risk_before=row["risk_before"], risk_after=row["risk_after"], suppressed=bool(row["suppressed"]),
            review_state=row["review_state"], review_note=row["review_note"],
            reviewed_at=_dt(row["reviewed_at"]), snoozed_until=_dt(row["snoozed_until"]),
            policy_id=row["policy_id"], alerted_at=_dt(row["alerted_at"]),
        )

    def get_change_event(self, event_id: int) -> ChangeEvent | None:
        row = self._conn.execute("SELECT * FROM change_events WHERE id = ?", (event_id,)).fetchone()
        return self._row_to_change_event(row) if row else None

    def change_events(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        mac: str | None = None,
        change_types: list[str] | None = None,
        limit: int | None = None,
    ) -> list[ChangeEvent]:
        """Changes, newest first - an indexed range query. Further
        filtering (significance, review state, trust, category) is cheap
        and done by callers on this bounded result."""

        clauses: list[str] = []
        params: list[object] = []
        if since is not None:
            clauses.append("occurred_at >= ?")
            params.append(_iso(since))
        if until is not None:
            clauses.append("occurred_at <= ?")
            params.append(_iso(until))
        if mac is not None:
            clauses.append("mac = ?")
            params.append(normalize_mac(mac))
        if change_types:
            clauses.append(f"change_type IN ({','.join('?' * len(change_types))})")
            params.extend(change_types)
        sql = "SELECT * FROM change_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY occurred_at DESC, id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        return [self._row_to_change_event(row) for row in self._conn.execute(sql, params).fetchall()]

    def update_change_review(
        self,
        event_id: int,
        *,
        review_state: str,
        now: datetime,
        note: str | None | object = _UNSET,
        snoozed_until: datetime | None = None,
    ) -> ChangeEvent | None:
        """Set one change's review state (``note`` left unchanged unless
        given). ``None`` if no such change."""

        current = self.get_change_event(event_id)
        if current is None:
            return None
        new_note = current.review_note if note is _UNSET else note
        self._conn.execute(
            "UPDATE change_events SET review_state = ?, review_note = ?, reviewed_at = ?, snoozed_until = ? "
            "WHERE id = ?",
            (
                review_state, new_note, _iso(now),
                _iso(snoozed_until) if snoozed_until else None, event_id,
            ),
        )
        self._conn.commit()
        return self.get_change_event(event_id)

    def set_change_policy(self, event_id: int, policy_id: str | None, *, alerted_at: datetime | None) -> None:
        self._conn.execute(
            "UPDATE change_events SET policy_id = ?, alerted_at = ? WHERE id = ?",
            (policy_id, _iso(alerted_at) if alerted_at else None, event_id),
        )
        self._conn.commit()

    # --- Know When It Changes: cursors over append-only tables ----------

    def get_cursor(self, name: str) -> int | None:
        row = self._conn.execute("SELECT position FROM change_cursors WHERE name = ?", (name,)).fetchone()
        return int(row["position"]) if row else None

    def set_cursor(self, name: str, position: int) -> None:
        self._conn.execute(
            "INSERT INTO change_cursors (name, position) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET position = excluded.position",
            (name, position),
        )
        self._conn.commit()

    def max_event_id(self) -> int:
        return int(self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])

    def events_after_id(self, event_id: int, *, limit: int = 1000) -> list[tuple[int, DeviceEvent]]:
        """Lifecycle events with ``id > event_id``, oldest first, each with
        its row id - for the change detector's cursor."""

        rows = self._conn.execute(
            "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?", (event_id, limit)
        ).fetchall()
        return [
            (
                row["id"],
                DeviceEvent(
                    mac=row["mac"], event_type=row["event_type"], timestamp=_parse_dt(row["timestamp"]),
                    ip=row["ip"], hostname=row["hostname"],
                ),
            )
            for row in rows
        ]

    def last_event_before(self, mac: str, event_id: int, *, event_type: str) -> DeviceEvent | None:
        row = self._conn.execute(
            "SELECT * FROM events WHERE mac = ? AND id < ? AND event_type = ? ORDER BY id DESC LIMIT 1",
            (normalize_mac(mac), event_id, event_type),
        ).fetchone()
        if row is None:
            return None
        return DeviceEvent(
            mac=row["mac"], event_type=row["event_type"], timestamp=_parse_dt(row["timestamp"]),
            ip=row["ip"], hostname=row["hostname"],
        )

    def max_dhcp_server_finding_id(self) -> int:
        return int(self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM dhcp_server_findings").fetchone()[0])

    def dhcp_server_findings_after_id(self, finding_id: int, *, limit: int = 1000) -> list[sqlite3.Row]:
        """Unapproved DHCP-server findings with ``id > finding_id``, oldest
        first, as raw rows - for the change detector's cursor."""

        return self._conn.execute(
            "SELECT * FROM dhcp_server_findings WHERE id > ? AND approved_at_observation = 0 "
            "ORDER BY id ASC LIMIT ?",
            (finding_id, limit),
        ).fetchall()

    def dhcp_server_source_macs_since(self, since: datetime) -> set[str]:
        """MACs that sent an unapproved DHCP server reply since ``since`` -
        a risk factor for that device (see :mod:`lanfence.risk`)."""

        rows = self._conn.execute(
            "SELECT DISTINCT source_mac FROM dhcp_server_findings "
            "WHERE approved_at_observation = 0 AND observed_at >= ? AND source_mac IS NOT NULL",
            (_iso(since),),
        ).fetchall()
        macs = set()
        for row in rows:
            try:
                macs.add(normalize_mac(row["source_mac"]))
            except ValueError:
                continue
        return macs

    # --- Know When It Changes: baselines ---------------------------------

    @staticmethod
    def _row_to_baseline(row: sqlite3.Row) -> DeviceBaseline:
        return DeviceBaseline(
            mac=row["mac"], started_at=_parse_dt(row["started_at"]),
            established_at=_parse_dt(row["established_at"]) if row["established_at"] else None,
            excluded_signals=json.loads(row["excluded_signals"]), ipv4=row["ipv4"], hostname=row["hostname"],
            identity_category=row["identity_category"], identity_manufacturer=row["identity_manufacturer"],
            trusted=bool(row["trusted"]),
            inspection_at=_parse_dt(row["inspection_at"]) if row["inspection_at"] else None,
            unknown_present_event_id=row["unknown_present_event_id"],
        )

    def get_baseline(self, mac: str) -> DeviceBaseline | None:
        row = self._conn.execute(
            "SELECT * FROM device_baselines WHERE mac = ?", (normalize_mac(mac),)
        ).fetchone()
        return self._row_to_baseline(row) if row else None

    def all_baselines(self) -> dict[str, DeviceBaseline]:
        rows = self._conn.execute("SELECT * FROM device_baselines").fetchall()
        return {row["mac"]: self._row_to_baseline(row) for row in rows}

    def save_baseline(self, baseline: DeviceBaseline, *, now: datetime) -> None:
        self._conn.execute(
            "INSERT INTO device_baselines (mac, started_at, established_at, excluded_signals, ipv4, hostname, "
            "identity_category, identity_manufacturer, trusted, inspection_at, unknown_present_event_id, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(mac) DO UPDATE SET started_at = excluded.started_at, "
            "established_at = excluded.established_at, excluded_signals = excluded.excluded_signals, "
            "ipv4 = excluded.ipv4, hostname = excluded.hostname, "
            "identity_category = excluded.identity_category, "
            "identity_manufacturer = excluded.identity_manufacturer, trusted = excluded.trusted, "
            "inspection_at = excluded.inspection_at, "
            "unknown_present_event_id = excluded.unknown_present_event_id, updated_at = excluded.updated_at",
            (
                normalize_mac(baseline.mac), _iso(baseline.started_at),
                _iso(baseline.established_at) if baseline.established_at else None,
                json.dumps(sorted(set(baseline.excluded_signals))), baseline.ipv4, baseline.hostname,
                baseline.identity_category, baseline.identity_manufacturer, int(baseline.trusted),
                _iso(baseline.inspection_at) if baseline.inspection_at else None,
                baseline.unknown_present_event_id, _iso(now),
            ),
        )
        self._conn.commit()

    def delete_baseline(self, mac: str) -> None:
        """Forget what's normal for ``mac`` (both tables) so it's learned
        again from scratch. Change history is kept."""

        mac = normalize_mac(mac)
        self._conn.execute("DELETE FROM device_baselines WHERE mac = ?", (mac,))
        self._conn.execute("DELETE FROM baseline_items WHERE mac = ?", (mac,))
        self._conn.commit()

    @staticmethod
    def _row_to_baseline_item(row: sqlite3.Row) -> BaselineItem:
        return BaselineItem(
            mac=row["mac"], signal=row["signal"], value=row["value"], in_baseline=bool(row["in_baseline"]),
            origin=row["origin"], present=bool(row["present"]), first_seen=_parse_dt(row["first_seen"]),
            last_seen=_parse_dt(row["last_seen"]),
            removed_at=_parse_dt(row["removed_at"]) if row["removed_at"] else None,
        )

    def baseline_items(self, mac: str | None = None) -> list[BaselineItem]:
        if mac is None:
            rows = self._conn.execute("SELECT * FROM baseline_items ORDER BY mac, signal, value").fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM baseline_items WHERE mac = ? ORDER BY signal, value", (normalize_mac(mac),)
            ).fetchall()
        return [self._row_to_baseline_item(row) for row in rows]

    def save_baseline_item(self, item: BaselineItem) -> None:
        mac = normalize_mac(item.mac)
        self._conn.execute(
            "INSERT INTO baseline_items (mac, signal, value, in_baseline, origin, present, first_seen, last_seen, "
            "removed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(mac, signal, value) DO UPDATE SET in_baseline = excluded.in_baseline, "
            "origin = excluded.origin, present = excluded.present, last_seen = excluded.last_seen, "
            "removed_at = excluded.removed_at",
            (
                mac, item.signal, item.value, int(item.in_baseline), item.origin, int(item.present),
                _iso(item.first_seen), _iso(item.last_seen), _iso(item.removed_at) if item.removed_at else None,
            ),
        )
        self._conn.execute(
            "DELETE FROM baseline_items WHERE mac = ? AND rowid NOT IN (SELECT rowid FROM baseline_items "
            "WHERE mac = ? ORDER BY in_baseline DESC, present DESC, last_seen DESC LIMIT ?)",
            (mac, mac, _MAX_BASELINE_ITEMS_PER_MAC),
        )
        self._conn.commit()

    # --- Know When It Changes: current risk --------------------------------

    @staticmethod
    def _row_to_risk(row: sqlite3.Row) -> RiskAssessment:
        return RiskAssessment(
            score=row["score"], level=row["level"],
            contributions=[RiskContribution(**c) for c in json.loads(row["contributions"])],
            recommendation=row["recommendation"], assessed_at=_parse_dt(row["assessed_at"]),
        )

    def get_risk(self, mac: str) -> RiskAssessment | None:
        row = self._conn.execute("SELECT * FROM device_risk WHERE mac = ?", (normalize_mac(mac),)).fetchone()
        return self._row_to_risk(row) if row else None

    def all_risk(self) -> dict[str, RiskAssessment]:
        return {row["mac"]: self._row_to_risk(row) for row in self._conn.execute("SELECT * FROM device_risk")}

    def save_risk(self, mac: str, assessment: RiskAssessment, *, now: datetime) -> None:
        self._conn.execute(
            "INSERT INTO device_risk (mac, score, level, contributions, recommendation, assessed_at) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(mac) DO UPDATE SET score = excluded.score, "
            "level = excluded.level, contributions = excluded.contributions, "
            "recommendation = excluded.recommendation, assessed_at = excluded.assessed_at",
            (
                normalize_mac(mac), assessment.score, assessment.level,
                json.dumps([c.model_dump() for c in assessment.contributions], separators=(",", ":")),
                assessment.recommendation, _iso(now),
            ),
        )
        self._conn.commit()

    def all_inspections(self) -> dict[str, InspectionResult]:
        return {
            row["mac"]: InspectionResult(
                mac=row["mac"], ip=row["ip"], method=row["method"], observed_at=_parse_dt(row["observed_at"]),
                open_ports=[InspectedPort(**p) for p in json.loads(row["open_ports"])],
                platform_guess=row["platform_guess"], platform_confidence=row["platform_confidence"],
                platform_reasons=json.loads(row["platform_reasons"]),
            )
            for row in self._conn.execute("SELECT * FROM device_inspections")
        }
