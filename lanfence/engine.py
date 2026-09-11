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
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.fingerprint import SignatureMatch, SignatureSet, fingerprint_device
from lanfence.logging_config import get_logger
from lanfence.models import Device, DeviceEvent, EventType, Finding, ScanResult

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
) -> tuple[Device, EventType | None, list[Finding]]:
    """Fold one MAC/IP sighting into the database and return what changed."""

    hostname = scanner.resolve_hostname(ip, timeout=cfg.scan.dns_timeout_seconds) if cfg.scan.resolve_hostnames else None
    vendor, matches = fingerprint_device(mac, hostname, signatures=signatures, vendor_file=cfg.vendor_file)
    device, event_type = store.observe(mac=mac, ip=ip, hostname=hostname, vendor=vendor, seen_at=seen_at)

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

    Unlike a passive sighting, a completed active sweep is authoritative for
    "what's online right now": any previously-online device not seen in this
    sweep is marked offline (a ``disconnected`` event) - but only if at least
    one scan mechanism actually ran. If every mechanism failed (e.g. no root
    this round), we have no information at all, and calling a device offline
    on the strength of no information would flood the database with false
    disconnects; ``mark_offline`` is skipped entirely in that case.
    """

    started_at = utcnow()
    iface = interface or cfg.scan.interface or scanner.default_interface()
    net = subnet or cfg.scan.subnet or scanner.local_subnet(iface)
    errors: list[str] = []
    sightings: list[scanner.ArpSighting] = []
    any_scan_succeeded = False

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
            any_scan_succeeded = True
        except (scanner.ScannerUnavailable, ValueError) as exc:
            errors.append(str(exc))

    if cfg.scan.ipv6:
        try:
            sightings.extend(
                scanner.active_scan_v6(interface=iface, timeout=cfg.scan.active_scan_timeout_seconds)
            )
            any_scan_succeeded = True
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
        )
        still_online.add(mac)
        devices.append(device)
        if event_type is not None:
            events.append(
                DeviceEvent(mac=mac, event_type=event_type, timestamp=sighting.seen_at,
                            ip=sighting.ip, hostname=device.hostname)
            )
        findings.extend(dev_findings)

    if any_scan_succeeded:
        events.extend(store.mark_offline(still_online, as_of=utcnow()))

    return ScanResult(
        started_at=started_at, ended_at=utcnow(), interface=iface, subnet=net,
        mode="active", devices=devices, events=events, findings=findings, errors=errors,
    )
