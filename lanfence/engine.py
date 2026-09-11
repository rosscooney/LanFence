# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Ties scanning, fingerprinting, the allowlist and the database together.

This is the one place that turns a raw ARP sighting into a :class:`Device`
update, a lifecycle :class:`DeviceEvent`, and any :class:`Finding` an operator
should see - used identically by ``lanfence scan`` (one sweep) and
``lanfence monitor`` (repeated sweeps plus passive sightings as they arrive).
"""

from __future__ import annotations

from datetime import datetime, timezone

from lanfence import scanner
from lanfence.allowlist import Allowlist
from lanfence.config import AlertConfig, Config
from lanfence.db import DeviceStore
from lanfence.fingerprint import SignatureMatch, SignatureSet, fingerprint_device
from lanfence.logging_config import get_logger
from lanfence.models import Device, DeviceEvent, EventType, Finding, ScanResult
from lanfence.netutil import normalize_mac

log = get_logger("engine")

_SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _top_severity(matches: list[SignatureMatch]) -> str | None:
    if not matches:
        return None
    return max((m.severity for m in matches), key=lambda s: _SEVERITY_RANK[s])


def build_findings(device: Device, event_type: EventType | None, matches: list[SignatureMatch]) -> list[Finding]:
    """Plain-language findings for one device's lifecycle transition.

    Routine "still online" refreshes and disconnects produce no finding - a
    disconnect is a lifecycle fact (see ``lanfence report``), not something to
    alert on. Only a device newly joining, or reappearing after being offline,
    is worth an operator's attention.
    """

    if event_type in (None, "disconnected"):
        return []

    top = _top_severity(matches)
    evidence = [
        f"MAC: {device.mac}",
        f"IP: {device.ip or '[unknown]'}",
        f"Hostname: {device.hostname or '[unknown]'}",
        f"Vendor: {device.vendor or '[unknown]'}",
    ]
    evidence.extend(m.evidence for m in matches)
    rationale = " ".join(m.description for m in matches) or (
        "No built-in fingerprint signature matched this device; its identity is unverified."
    )

    if device.allowlisted:
        label = device.allowlist_name or device.mac
        if event_type == "new_device":
            title = f"New allowlisted device connected: {label}"
        else:
            title = f"Allowlisted device reappeared: {label}"
        return [
            Finding(
                mac=device.mac,
                title=title,
                severity="info",
                rationale=f"This MAC is on your allowlist as {label!r}. " + rationale,
                recommendation="No action needed - this device is trusted.",
                evidence=evidence,
            )
        ]

    if event_type == "new_device":
        severity = top or "medium"
        title = "Unknown device connected"
        recommendation = (
            "Verify this device belongs on your network. If it's yours, run "
            f"`lanfence allow {device.mac}` to stop future alerts about it."
        )
    else:  # reappeared
        # A device you'd already seen before is lower-signal by default; only
        # keep shouting if it also carries a high-severity fingerprint match.
        severity = top if top == "high" else "info"
        title = "Previously seen (non-allowlisted) device reappeared"
        recommendation = (
            "This device was seen before and was not on your allowlist. If it's "
            f"yours, run `lanfence allow {device.mac}`; otherwise investigate."
        )

    return [
        Finding(
            mac=device.mac,
            title=title,
            severity=severity,
            rationale=rationale,
            recommendation=recommendation,
            evidence=evidence,
        )
    ]


def process_sighting(
    *,
    mac: str,
    ip: str,
    seen_at: datetime,
    store: DeviceStore,
    allowlist: Allowlist,
    signatures: SignatureSet,
    cfg: Config,
    hostname_hint: str | None = None,
    interface: str | None = None,
    subnet: str | None = None,
) -> tuple[Device, EventType | None, list[Finding]]:
    """Fold one MAC/IP sighting into the database and return what changed.

    ``hostname_hint`` - a self-reported name from a DHCP sighting - is used
    as-is instead of doing a reverse-DNS lookup: a device telling the network
    its own name moments ago is at least as trustworthy as a PTR record (both
    are equally spoofable), and skips a DNS round-trip. ``None`` (every ARP/
    NDP sighting) falls back to reverse-DNS exactly as before.

    ``interface``/``subnet`` are passed straight through to
    :meth:`lanfence.db.DeviceStore.observe` as discovery provenance for the
    offline-grace-period feature - see its docstring.
    """

    hostname = hostname_hint
    if not hostname and cfg.scan.resolve_hostnames:
        hostname = scanner.resolve_hostname(ip, timeout=cfg.scan.dns_timeout_seconds)
    vendor, matches = fingerprint_device(mac, hostname, signatures=signatures, vendor_file=cfg.vendor_file)
    device, event_type = store.observe(
        mac=mac, ip=ip, hostname=hostname, vendor=vendor, seen_at=seen_at,
        interface=interface, subnet=subnet,
    )

    allow_entry = allowlist.match(mac)
    device = device.model_copy(
        update={
            "allowlisted": allow_entry is not None,
            "allowlist_name": allow_entry.name if allow_entry else None,
            "fingerprints": [m.category for m in matches],
        }
    )
    findings = build_findings(device, event_type, matches)
    return device, event_type, findings


def run_active_sweep(
    cfg: Config,
    store: DeviceStore,
    allowlist: Allowlist,
    signatures: SignatureSet,
    *,
    interface: str | None = None,
    subnet: str | None = None,
) -> ScanResult:
    """Run one active sweep - ARP, plus IPv6 neighbor discovery if enabled -
    and update the database.

    Unlike a passive sighting, a completed active sweep is the only place an
    offline transition is ever evaluated - elapsed wall time alone never
    disconnects a device. A previously-online device not seen in this sweep
    only actually goes offline (a ``disconnected`` event) once BOTH
    ``cfg.scan.offline_after_missed_scans`` consecutive *eligible* misses and
    ``cfg.scan.offline_grace_seconds`` of elapsed time since its last
    sighting have been reached; see :meth:`lanfence.db.DeviceStore.mark_offline`
    for exactly what makes a miss "eligible" (this sweep must have actually
    covered that device's known discovery path - interface, address family,
    and IPv4 subnet). If every scan mechanism failed this round (e.g. no root),
    there is no information at all, and ``mark_offline`` is skipped entirely -
    calling a device offline on the strength of no information would flood
    the database with false disconnects.
    """

    started_at = utcnow()
    iface = interface or cfg.scan.interface or scanner.default_interface()
    net = subnet or cfg.scan.subnet or scanner.local_subnet(iface)
    errors: list[str] = []
    sightings: list[scanner.ArpSighting] = []
    ipv4_covered = False
    ipv6_covered = False

    if net is None:
        errors.append(
            "could not determine a subnet to scan automatically; pass --subnet "
            "explicitly (e.g. --subnet 192.168.1.0/24) - IPv4 discovery skipped this sweep"
        )
    else:
        try:
            sightings.extend(
                scanner.active_scan(subnet=net, interface=iface, timeout=cfg.scan.active_scan_timeout_seconds)
            )
            ipv4_covered = True
        except (scanner.ScannerUnavailable, ValueError) as exc:
            errors.append(str(exc))

    if cfg.scan.ipv6:
        try:
            sightings.extend(
                scanner.active_scan_v6(interface=iface, timeout=cfg.scan.active_scan_timeout_seconds)
            )
            ipv6_covered = True
        except scanner.ScannerUnavailable as exc:
            errors.append(str(exc))

    latest = scanner.dedupe_latest(sightings)
    devices: list[Device] = []
    events: list[DeviceEvent] = []
    findings: list[Finding] = []
    still_online: set[str] = set()

    for mac, sighting in latest.items():
        device, event_type, dev_findings = process_sighting(
            mac=mac, ip=sighting.ip, seen_at=sighting.seen_at,
            store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
            interface=iface, subnet=net,
        )
        still_online.add(mac)
        devices.append(device)
        if event_type is not None:
            events.append(
                DeviceEvent(mac=mac, event_type=event_type, timestamp=sighting.seen_at,
                            ip=sighting.ip, hostname=device.hostname)
            )
        findings.extend(dev_findings)

    if ipv4_covered or ipv6_covered:
        events.extend(
            store.mark_offline(
                still_online, as_of=utcnow(),
                grace_seconds=cfg.scan.offline_grace_seconds,
                missed_after=cfg.scan.offline_after_missed_scans,
                ipv4_covered=ipv4_covered, ipv4_subnet=net,
                ipv6_covered=ipv6_covered, interface=iface,
            )
        )

    return ScanResult(
        started_at=started_at, ended_at=utcnow(), interface=iface, subnet=net,
        mode="active", devices=devices, events=events, findings=findings, errors=errors,
    )


def filter_rate_limited(
    findings: list[Finding], store: DeviceStore, cfg: AlertConfig, *, now: datetime
) -> list[Finding]:
    """Findings actually worth sending to external alert channels right now.

    Throttles only the *push* side (``alerts.dispatch``) via a per-MAC
    cooldown in the database - the CLI table, JSON output, and the events/
    findings already written to the database are unaffected. Processes
    highest severity first so an escalation within the same batch is never
    itself suppressed by a lower-severity finding for the same MAC processed
    earlier. See :meth:`lanfence.db.DeviceStore.due_for_alert`.
    """

    ordered = sorted(findings, key=lambda f: -_SEVERITY_RANK[f.severity])
    return [
        finding for finding in ordered
        if store.due_for_alert(
            finding.mac, finding.severity, now=now, cooldown_seconds=cfg.rate_limit_seconds
        )
    ]


def filter_snoozed(findings: list[Finding], store: DeviceStore, *, now: datetime) -> list[Finding]:
    """Findings for a MAC that is *not* currently snoozed.

    Applied before :func:`filter_rate_limited` so a snoozed device's
    suppressed findings never reach ``due_for_alert`` - a snooze must not
    consume cooldown bookkeeping it never actually used. Only throttles
    external dispatch: the caller's own copy of ``findings`` (for CLI/JSON
    output, and whatever was already written to the database) is untouched.
    """

    return [f for f in findings if not store.is_snoozed(f.mac, now=now)]


def apply_self_trust(allowlist: Allowlist, *, interface: str | None) -> None:
    """Make LAN Fence trust its own MAC address on ``interface``, so its own
    ARP/ND traffic - inevitably visible to a passive capture, and sometimes
    even to its own active sweep - is never treated as an unknown device.

    In-memory only: mutates ``allowlist.entries`` directly and never touches
    ``allowlist.path`` or calls :meth:`Allowlist.save`, so this is never
    written into the operator's own curated allowlist file - if the host's
    interface or MAC changes later (new hardware, a different NIC), nothing
    stale is left behind. If the operator has *already* explicitly trusted
    this exact MAC themselves (their own entry, their own name), that choice
    is left alone rather than overwritten.
    """

    self_mac = scanner.local_mac(interface)
    if self_mac is None:
        return
    try:
        norm = normalize_mac(self_mac)
    except ValueError:
        return
    if allowlist.match(norm) is None:
        allowlist.add(norm, "This host (running LAN Fence)", "auto-detected - LAN Fence trusts itself")


def build_inventory(store: DeviceStore, allowlist: Allowlist) -> list[Device]:
    """Every previously observed device, with current allowlist/review state
    joined in. Does not perform a scan - purely a database read."""

    inventory: list[Device] = []
    for device in store.all_devices():
        review = store.get_review(device.mac)
        allow_entry = allowlist.match(device.mac)
        inventory.append(
            device.model_copy(
                update={
                    "allowlisted": allow_entry is not None,
                    "allowlist_name": allow_entry.name if allow_entry else None,
                    "review_state": review.state,
                    "review_notes": review.notes,
                    "snoozed_until": review.snoozed_until,
                }
            )
        )
    return inventory


def is_review_needed(device: Device, *, now: datetime) -> bool:
    """Untrusted, not actively snoozed, and not already flagged for
    investigation. An expired snooze (``snoozed_until`` in the past) does not
    count as active, so the device is back in the review queue."""

    if device.allowlisted or device.review_state == "investigating":
        return False
    if device.review_state == "snoozed" and device.snoozed_until is not None and device.snoozed_until > now:
        return False
    return True
