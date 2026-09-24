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
from lanfence.models import Device, DeviceEvent, DeviceMetadata, EventType, Finding, ScanResult
from lanfence.netutil import normalize_mac

log = get_logger("engine")

_SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _top_severity(matches: list[SignatureMatch]) -> str | None:
    if not matches:
        return None
    return max((m.severity for m in matches), key=lambda s: _SEVERITY_RANK[s])


def _device_evidence_lines(
    *, mac: str, ip: str | None, hostname: str | None, vendor: str | None,
    allowlisted: bool = False, allowlist_name: str | None = None,
    metadata: DeviceMetadata | None = None,
) -> list[str]:
    """Standard identifying context for a device-scoped finding's evidence
    list - the name we gave it first (its allowlist name, when trusted),
    then MAC/IP/hostname/vendor, then any operator-set metadata (owner/
    location - see :class:`~lanfence.models.DeviceMetadata`), each
    included only when actually set, so a device nobody has annotated
    doesn't get a wall of "[unknown]" lines. Shared by every device-scoped
    finding (:func:`build_findings`, :func:`evaluate_availability`, and
    ``process_sighting``'s "recovered" finding) so an operator reading a
    finding - in an alert email or anywhere else evidence is shown - gets
    enough context to act on it without a separate lookup.
    """

    lines = []
    if allowlisted:
        lines.append(f"Name: {allowlist_name or mac}")
    lines.extend([
        f"MAC: {mac}",
        f"IP: {ip or '[unknown]'}",
        f"Hostname: {hostname or '[unknown]'}",
        f"Vendor: {vendor or '[unknown]'}",
    ])
    if metadata is not None:
        if metadata.owner:
            lines.append(f"Owner: {metadata.owner}")
        if metadata.location:
            lines.append(f"Location: {metadata.location}")
    return lines


def build_findings(device: Device, event_type: EventType | None, matches: list[SignatureMatch]) -> list[Finding]:
    """Plain-language findings for one device's lifecycle transition.

    Routine "still online" refreshes and disconnects produce no finding - a
    disconnect is a lifecycle fact (see ``lanfence report``), not something to
    alert on. Only a device newly joining, or reappearing after being offline,
    is worth an operator's attention.

    Every finding here is tagged with a :data:`~lanfence.models.FindingKind`
    rather than left to be inferred from its title later:

    - ``new_device`` is always ``"security"`` - a MAC never seen before is
      inherently worth a look, regardless of any presence policy (a first
      discovery is never suppressed - see ``lanfence device --presence``).
    - A routine, non-allowlisted ``reappeared`` with no high-severity
      signature match is ``"lifecycle"`` - purely "this MAC came back,"
      nothing independently security-relevant.
    - A routine ``reappeared`` that *also* carries a high-severity signature
      match is split into two findings: a ``"lifecycle"`` one (the routine
      announcement) and a separate ``"security"`` one (the signature
      evidence, standing on its own) - so an intermittent-presence device
      (see :func:`lanfence.engine.process_sighting`) can have the former
      suppressed without ever losing the latter.
    - An allowlisted device's reappearance stays a single ``"lifecycle"``
      finding at ``info`` - trust already downgrades it, and it never
      carries independent signature-based severity today.
    """

    if event_type in (None, "disconnected"):
        return []

    top = _top_severity(matches)
    evidence = _device_evidence_lines(
        mac=device.mac, ip=device.ip, hostname=device.hostname, vendor=device.vendor,
        allowlisted=device.allowlisted, allowlist_name=device.allowlist_name, metadata=device.metadata,
    )
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
        result = [
            Finding(
                mac=device.mac,
                title=title,
                severity="info",
                kind="security" if event_type == "new_device" else "lifecycle",
                rationale=f"This MAC is on your allowlist as {label!r}. " + rationale,
                recommendation="No action needed - this device is trusted.",
                evidence=evidence,
            )
        ]
    elif event_type == "new_device":
        severity = top or "medium"
        title = "Unknown device connected"
        recommendation = (
            "Verify this device belongs on your network. If it's yours, run "
            f"`lanfence allow {device.mac}` to stop future alerts about it."
        )
        result = [
            Finding(
                mac=device.mac, title=title, severity=severity, kind="security",
                rationale=rationale, recommendation=recommendation, evidence=evidence,
            )
        ]
    else:
        # reappeared, not allowlisted: a device you'd already seen before is
        # lower-signal by default - just the routine lifecycle announcement -
        # unless it also carries a high-severity fingerprint match, in which
        # case that evidence stands as its own, independently-suppressible
        # security finding (see the docstring above).
        lifecycle_finding = Finding(
            mac=device.mac,
            title="Previously seen (non-allowlisted) device reappeared",
            severity="info",
            kind="lifecycle",
            rationale="This device was seen before and was not on your allowlist.",
            recommendation=(
                f"If it's yours, run `lanfence allow {device.mac}`; otherwise investigate."
            ),
            evidence=evidence,
        )
        if top != "high":
            result = [lifecycle_finding]
        else:
            high_matches = [m for m in matches if m.severity == "high"]
            security_finding = Finding(
                mac=device.mac,
                title="Rogue-device signature matched on reappearance",
                severity="high",
                kind="security",
                rationale=" ".join(m.description for m in high_matches),
                recommendation="Investigate this device - a known rogue-device signature matched.",
                evidence=evidence + [m.evidence for m in high_matches],
            )
            result = [security_finding, lifecycle_finding]

    if device.presence_policy == "intermittent":
        # Routine come-and-go is expected for this device - drop only the
        # "sole purpose is announcing routine absence or return" findings.
        # A first-ever discovery (kind="security" even when untrusted) and
        # any independent security evidence are never suppressed.
        result = [f for f in result if f.kind != "lifecycle"]
    return result


def coalesce_sightings(sightings: list[scanner.ArpSighting]) -> list[scanner.ArpSighting]:
    """Collapse repeated, truly-identical sightings within one batch (same
    mac/ip/hostname/source/interface) down to the single most-recently-seen one,
    while leaving every distinct sighting - a different IP (dual-stack), a
    changed hostname, a different discovery source - completely untouched.

    Used by `lanfence monitor`'s passive-queue drain loop to cut the
    per-tick database work for a burst of duplicate broadcast/multicast
    traffic (the common case) without ever discarding a piece of evidence
    that wasn't a pure duplicate - "safe" coalescing, not lossy
    downsampling. Preserves each distinct key's first-occurrence position
    in the output, so processing order for genuinely different sightings
    is otherwise unchanged.
    """

    latest: dict[tuple[str, str, str | None, str, str | None], scanner.ArpSighting] = {}
    order: list[tuple[str, str, str | None, str, str | None]] = []
    for sighting in sightings:
        key = (sighting.mac, sighting.ip, sighting.hostname, sighting.source, sighting.interface)
        if key not in latest:
            order.append(key)
            latest[key] = sighting
        elif sighting.seen_at >= latest[key].seen_at:
            latest[key] = sighting
    return [latest[key] for key in order]


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
    source: str = "arp",
) -> tuple[Device, EventType | None, list[Finding]]:
    """Fold one MAC/IP sighting into the database and return what changed.

    ``hostname_hint`` - a self-reported name from a DHCP sighting - is used
    as-is instead of doing a reverse-DNS lookup: a device telling the network
    its own name moments ago is at least as trustworthy as a PTR record (both
    are equally spoofable), and skips a DNS round-trip. ``None`` (every ARP/
    NDP sighting) falls back to reverse-DNS exactly as before. Either way,
    the resulting name (if any) is recorded as durable evidence tagged with
    which of the two produced it (``dhcp_option_12``/``reverse_dns``) - a
    failed lookup (``hostname`` stays ``None``) records nothing, never
    erasing name evidence already on file.

    ``interface``/``subnet`` are passed straight through to
    :meth:`lanfence.db.DeviceStore.observe` as discovery provenance for the
    offline-grace-period feature - see its docstring. ``source`` (see
    :data:`lanfence.scanner.SightingSource`) is likewise threaded through as
    address-evidence provenance - only ``"arp"``/``"ipv6_nd"`` (directly
    observed) are ever recorded as address evidence; a mere DHCP client
    request/offer (``"dhcp_client"``) still updates presence/coverage above
    but is deliberately never trusted as evidence of the address itself
    (see ``DeviceStore.observe``'s docstring).

    An always-on device reappearing after an absence that already triggered
    an availability (absence) finding gets exactly one additional info-
    severity recovery finding here, and its episode state is cleared so the
    next absence starts a fresh one - see ``lanfence device --presence``.
    """

    hostname = hostname_hint
    hostname_source = "dhcp_option_12" if hostname_hint else None
    if not hostname and cfg.scan.resolve_hostnames:
        hostname = scanner.resolve_hostname(ip, timeout=cfg.scan.dns_timeout_seconds)
        if hostname:
            hostname_source = "reverse_dns"
    vendor, matches = fingerprint_device(mac, hostname, signatures=signatures, vendor_file=cfg.vendor_file)
    device, event_type = store.observe(
        mac=mac, ip=ip, hostname=hostname, vendor=vendor, seen_at=seen_at,
        interface=interface, subnet=subnet, source=source, hostname_source=hostname_source,
    )

    allow_entry = allowlist.match(mac)
    presence = store.get_presence(mac)
    # Only fetched when a finding could actually result (build_findings'
    # own no-op guard below) - skips the extra query on the overwhelmingly
    # common "still online, nothing happened" refresh.
    metadata = store.get_device_metadata(mac) if event_type not in (None, "disconnected") else None
    device = device.model_copy(
        update={
            "allowlisted": allow_entry is not None,
            "allowlist_name": allow_entry.name if allow_entry else None,
            "fingerprints": [m.category for m in matches],
            "presence_policy": presence.policy,
            "offline_after_seconds": presence.offline_after_seconds,
            "metadata": metadata,
        }
    )
    findings = build_findings(device, event_type, matches)

    if event_type == "reappeared" and presence.availability_alerted:
        # Trust must not downgrade an explicitly requested availability
        # finding - this recovery fires regardless of allowlist status.
        findings.append(
            Finding(
                mac=device.mac,
                title="Always-on device recovered",
                severity="info",
                kind="availability",
                rationale=(
                    "This device is policy'd as always-on and had been confirmed absent "
                    "long enough to trigger an availability alert; it has now reappeared."
                ),
                recommendation="No action needed.",
                evidence=_device_evidence_lines(
                    mac=device.mac, ip=device.ip, hostname=device.hostname, vendor=device.vendor,
                    allowlisted=device.allowlisted, allowlist_name=device.allowlist_name,
                    metadata=device.metadata,
                ),
            )
        )
        store.set_availability_alerted(mac, False, updated_at=seen_at)

    return device, event_type, findings


def evaluate_availability(
    store: DeviceStore,
    cfg: Config,
    *,
    as_of: datetime,
    ipv4_covered: bool,
    ipv4_subnet: str | None,
    ipv6_covered: bool,
    interface: str | None,
    allowlist: Allowlist | None = None,
) -> list[Finding]:
    """One medium-severity availability finding per always-on device whose
    absence has just reached its effective delay - see
    :meth:`lanfence.db.DeviceStore.evaluate_availability` for the
    eligibility rule (an already-offline, not-yet-alerted, always-on
    device, evaluated only against a sweep that actually covered its known
    discovery path). Trust never downgrades this - it fires at ``medium``
    regardless of allowlist status. Call this once per eligible active
    sweep, alongside :func:`run_active_sweep`'s ``mark_offline`` call.
    ``allowlist`` puts a trusted device's name at the top of its evidence,
    the same as every other device-scoped finding.
    """

    due = store.evaluate_availability(
        as_of=as_of, default_offline_after_seconds=cfg.scan.offline_grace_seconds,
        ipv4_covered=ipv4_covered, ipv4_subnet=ipv4_subnet,
        ipv6_covered=ipv6_covered, interface=interface,
    )
    # One bulk query for every due device's metadata, not one per device.
    metadata_by_mac = store.device_metadata_for_macs([item["mac"] for item in due])
    findings: list[Finding] = []
    for item in due:
        delay = item["offline_after_seconds"]
        allow_entry = allowlist.match(item["mac"]) if allowlist is not None else None
        findings.append(
            Finding(
                mac=item["mac"],
                title="Always-on device has been absent longer than expected",
                severity="medium",
                kind="availability",
                rationale=(
                    "This device is policy'd as always-on and has not been seen for at "
                    f"least {delay:.0f}s since it was confirmed offline."
                ),
                recommendation="Check that this device is powered on and connected.",
                evidence=_device_evidence_lines(
                    mac=item["mac"], ip=item["ip"], hostname=item["hostname"], vendor=item["vendor"],
                    allowlisted=allow_entry is not None, allowlist_name=allow_entry.name if allow_entry else None,
                    metadata=metadata_by_mac.get(item["mac"]),
                ),
            )
        )
    return findings


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

    # Every sighting is processed - not deduped down to one per MAC first.
    # A dual-stack device (or one seen via more than one mechanism in the
    # same sweep) must have *all* of its addresses reach evidence storage
    # (see DeviceStore.record_address_evidence), not just whichever sighting
    # happened to be "latest". This does not risk duplicate lifecycle
    # events/findings: observe() only ever reports a real transition
    # (new_device/reappeared) on the *first* call for a MAC that's actually
    # offline/unknown - a second call for the same MAC, moments later in
    # the same sweep, always finds it already online and reports a routine
    # (event_type=None) refresh instead.
    devices_by_mac: dict[str, Device] = {}
    events: list[DeviceEvent] = []
    findings: list[Finding] = []
    still_online: set[str] = set()

    for sighting in sightings:
        try:
            mac = normalize_mac(sighting.mac)
        except ValueError:
            continue
        device, event_type, dev_findings = process_sighting(
            mac=mac, ip=sighting.ip, seen_at=sighting.seen_at,
            store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
            interface=iface, subnet=net, source=sighting.source,
        )
        still_online.add(mac)
        devices_by_mac[mac] = device
        if event_type is not None:
            events.append(
                DeviceEvent(mac=mac, event_type=event_type, timestamp=sighting.seen_at,
                            ip=sighting.ip, hostname=device.hostname)
            )
        findings.extend(dev_findings)

    if ipv4_covered or ipv6_covered:
        as_of = utcnow()
        if ipv4_covered and net is not None and cfg.scan.offline_retry_probe:
            _retry_devices_due_for_offline(
                store, still_online, devices_by_mac, events, findings,
                as_of=as_of, cfg=cfg, allowlist=allowlist, signatures=signatures,
                interface=iface, subnet=net, ipv6_covered=ipv6_covered,
            )
        events.extend(
            store.mark_offline(
                still_online, as_of=as_of,
                grace_seconds=cfg.scan.offline_grace_seconds,
                missed_after=cfg.scan.offline_after_missed_scans,
                ipv4_covered=ipv4_covered, ipv4_subnet=net,
                ipv6_covered=ipv6_covered, interface=iface,
            )
        )
        findings.extend(
            evaluate_availability(
                store, cfg, as_of=as_of,
                ipv4_covered=ipv4_covered, ipv4_subnet=net,
                ipv6_covered=ipv6_covered, interface=iface, allowlist=allowlist,
            )
        )

    return ScanResult(
        started_at=started_at, ended_at=utcnow(), interface=iface, subnet=net,
        interfaces=[iface] if iface else [],
        mode="active", devices=list(devices_by_mac.values()), events=events, findings=findings, errors=errors,
        site_name=cfg.site.name, site_location=cfg.site.location,
    )


def resolve_scan_interfaces(cfg: Config, cli_interface: str | None = None) -> list[str]:
    """The interfaces this run should scan/sniff on. A ``--interface`` CLI
    override forces single-interface mode for that run; otherwise the
    ``scan.interfaces`` list from `lanfence setup`, then the legacy single
    ``scan.interface``, then one auto-detected default interface (empty
    only if even that can't be found)."""

    if cli_interface:
        return [cli_interface]
    if cfg.scan.interfaces:
        return list(cfg.scan.interfaces)
    if cfg.scan.interface:
        return [cfg.scan.interface]
    default = scanner.default_interface()
    return [default] if default else []


def run_active_sweep_multi(
    cfg: Config,
    store: DeviceStore,
    allowlist: Allowlist,
    signatures: SignatureSet,
    *,
    interfaces: list[str],
) -> ScanResult:
    """One :func:`run_active_sweep` per interface, merged into a single
    result. Each per-interface sweep is individually correct on its own -
    offline detection is already scoped to the interface a device was last
    seen on (see :meth:`lanfence.db.DeviceStore.mark_offline`), so a device
    on one interface is never marked offline by another interface's sweep.
    Each interface uses its own auto-detected subnet (``scan.subnet`` is
    ignored here). ``devices`` is every device any interface's sweep saw,
    one entry per MAC."""

    started_at = utcnow()
    # A configured scan.subnet names one network, so it can't apply to
    # every interface - each one auto-detects its own instead.
    per_iface_cfg = cfg.model_copy(update={"scan": cfg.scan.model_copy(update={"subnet": None})})
    devices_by_mac: dict[str, Device] = {}
    events: list[DeviceEvent] = []
    findings: list[Finding] = []
    errors: list[str] = []
    for iface in interfaces:
        result = run_active_sweep(per_iface_cfg, store, allowlist, signatures, interface=iface, subnet=None)
        devices_by_mac.update((device.mac, device) for device in result.devices)
        events.extend(result.events)
        findings.extend(result.findings)
        errors.extend(f"{iface}: {error}" for error in result.errors)
    return ScanResult(
        started_at=started_at, ended_at=utcnow(), interface=None, subnet=None, interfaces=list(interfaces),
        mode="active", devices=list(devices_by_mac.values()), events=events, findings=findings,
        errors=errors, site_name=cfg.site.name, site_location=cfg.site.location,
    )


def _retry_devices_due_for_offline(
    store: DeviceStore,
    still_online: set[str],
    devices_by_mac: dict[str, Device],
    events: list[DeviceEvent],
    findings: list[Finding],
    *,
    as_of: datetime,
    cfg: Config,
    allowlist: Allowlist,
    signatures: SignatureSet,
    interface: str | None,
    subnet: str,
    ipv6_covered: bool,
) -> None:
    """Give every device :meth:`lanfence.db.DeviceStore.mark_offline` is
    about to transition offline one last direct unicast ARP probe (see
    :func:`lanfence.scanner.arp_probe`) before accepting that verdict -
    see ``scan.offline_retry_probe``'s docstring in :mod:`lanfence.config`
    for why. An answering device is folded back in exactly like a real
    sighting (via :func:`process_sighting`) - ``still_online``/
    ``devices_by_mac``/``events``/``findings`` are updated in place so it
    reaches :func:`run_active_sweep`'s return value and is naturally
    excluded from the ``mark_offline`` call that follows this. IPv4 only -
    ARP has no IPv6 equivalent.

    The first permission/availability failure (:class:`~lanfence.scanner.ScannerUnavailable`)
    stops the retry pass early rather than retrying every remaining
    candidate the same losing way - the main sweep already ran
    successfully (that's how any candidate got here at all), so this is a
    non-fatal, silent skip of the retry step, not a sweep-wide error.
    """

    due = store.devices_due_for_offline(
        still_online, as_of=as_of,
        grace_seconds=cfg.scan.offline_grace_seconds,
        missed_after=cfg.scan.offline_after_missed_scans,
        ipv4_covered=True, ipv4_subnet=subnet,
        ipv6_covered=ipv6_covered, interface=interface,
    )
    if not due:
        return
    # `Device.ip` (from `get_device`) is only ever one preferred address,
    # possibly IPv6 even for a dual-stack device - the per-family lookup
    # (same one `build_inventory` uses for dual-stack display) is the only
    # reliable way to get a device's actual IPv4 address here.
    addresses_by_family = store.preferred_addresses_by_family_for_macs([d.mac for d in due])
    for candidate in due:
        ipv4 = addresses_by_family.get(candidate.mac, {}).get("ipv4")
        if not ipv4:
            continue
        try:
            reply = scanner.arp_probe(
                ipv4, interface=interface, timeout=cfg.scan.offline_retry_timeout_seconds,
            )
        except scanner.ScannerUnavailable as exc:
            log.warning("offline-retry ARP probe unavailable, skipping remaining candidates: %s", exc)
            return
        if reply is None:
            continue
        device, event_type, dev_findings = process_sighting(
            mac=candidate.mac, ip=reply.ip, seen_at=reply.seen_at,
            store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
            interface=interface, subnet=subnet, source=reply.source,
        )
        still_online.add(candidate.mac)
        devices_by_mac[candidate.mac] = device
        if event_type is not None:
            events.append(
                DeviceEvent(mac=candidate.mac, event_type=event_type, timestamp=reply.seen_at,
                            ip=reply.ip, hostname=device.hostname)
            )
        findings.extend(dev_findings)


def _alert_cooldown_key(finding: Finding) -> str:
    """The cooldown row identity for one finding - plain ``mac`` for every
    pre-existing, device-scoped finding kind (unchanged behavior), but a
    finding not about one device (``mac is None`` - kind ``availability`` or
    ``network_service``) needs an identity that isn't a MAC:

    - ``availability`` gets its own lane per phase
      (``mac#availability#<severity>``, and absence is always "medium" while
      recovery is always "info") so a recent absence alert can never
      swallow the recovery for the same MAC - they are independent
      notifications, not escalating variants of the same one.
    - ``network_service`` (e.g. an unexpected DHCP server) has no MAC at
      all - keyed by its own ``subject_id`` (interface/server-identifier)
      instead, so two different servers - or the same server on two
      interfaces - never share a cooldown row.

    See :meth:`lanfence.db.DeviceStore.due_for_alert`.
    """

    if finding.kind == "availability":
        return f"{finding.mac}#availability#{finding.severity}"
    if finding.kind == "network_service":
        return f"network_service#{finding.subject_id}#{finding.severity}"
    return finding.mac


def filter_rate_limited(
    findings: list[Finding], store: DeviceStore, cfg: AlertConfig, *, now: datetime
) -> list[Finding]:
    """Findings actually worth sending to external alert channels right now.

    Throttles the *push* side (``alerts.dispatch``) two ways - the CLI
    table, JSON output, and the events/findings already written to the
    database are unaffected by either:

    - A per-MAC (or, for a MAC-less finding, per-subject) cooldown (see
      :meth:`lanfence.db.DeviceStore.due_for_alert`).
    - A *global* cap on total dispatch volume within a fixed window (see
      :meth:`lanfence.db.DeviceStore.consume_global_alert_budget`),
      independent of the per-MAC cooldown above - a flood of findings from
      many distinct/rotating identities (e.g. randomized MACs) each
      individually pass their own per-MAC cooldown (it's the first time
      *that* key has ever alerted), so the per-MAC cooldown alone cannot
      bound total volume; the global cap does.

    Processes highest severity first so an escalation within the same
    batch is never itself suppressed by a lower-severity finding for the
    same subject processed earlier - an escalation still counts against
    the global cap, though, so it can't be used to bypass it.
    """

    ordered = sorted(findings, key=lambda f: -_SEVERITY_RANK[f.severity])
    result = []
    for finding in ordered:
        if not store.due_for_alert(
            finding.mac or "", finding.severity, now=now, cooldown_seconds=cfg.rate_limit_seconds,
            key=_alert_cooldown_key(finding),
        ):
            continue
        if not store.consume_global_alert_budget(
            now, max_per_window=cfg.global_rate_limit_max, window_seconds=cfg.global_rate_limit_window_seconds,
        ):
            continue
        result.append(finding)
    return result


def filter_snoozed(findings: list[Finding], store: DeviceStore, *, now: datetime) -> list[Finding]:
    """Findings for a MAC that is *not* currently snoozed.

    Applied before :func:`filter_rate_limited` so a snoozed device's
    suppressed findings never reach ``due_for_alert`` - a snooze must not
    consume cooldown bookkeeping it never actually used. Only throttles
    external dispatch: the caller's own copy of ``findings`` (for CLI/JSON
    output, and whatever was already written to the database) is untouched.

    A finding with no MAC (e.g. a DHCP-server finding) isn't about any one
    device, so snoozing - a per-device concept - can't apply to it; it
    always passes through unaffected.
    """

    return [f for f in findings if f.mac is None or not store.is_snoozed(f.mac, now=now)]


def apply_self_trust(allowlist: Allowlist, *, interface: str | list[str] | None) -> None:
    """Make LAN Fence trust its own MAC address on ``interface`` (or on each
    of them, given a list), so its own ARP/ND traffic - inevitably visible
    to a passive capture, and sometimes even to its own active sweep - is
    never treated as an unknown device.

    In-memory only: mutates ``allowlist.entries`` directly and never touches
    ``allowlist.path`` or calls :meth:`Allowlist.save`, so this is never
    written into the operator's own curated allowlist file - if the host's
    interface or MAC changes later (new hardware, a different NIC), nothing
    stale is left behind. If the operator has *already* explicitly trusted
    this exact MAC themselves (their own entry, their own name), that choice
    is left alone rather than overwritten.
    """

    if isinstance(interface, list):
        for name in interface:
            apply_self_trust(allowlist, interface=name)
        return
    self_mac = scanner.local_mac(interface)
    if self_mac is None:
        return
    try:
        norm = normalize_mac(self_mac)
    except ValueError:
        return
    if allowlist.match(norm) is None:
        allowlist.add(norm, "This host (running LAN Fence)", "auto-detected - LAN Fence trusts itself")


def _join_device_context(
    device: Device, *, review, presence, metadata: DeviceMetadata, allow_entry, addresses_by_family=None,
) -> Device:
    """The allowlist/review/presence/metadata join shared by
    :func:`build_inventory` (bulk) and :func:`build_device` (one MAC) - the
    single place this join is implemented, so `lanfence device`/`review`/
    `allow` and anything else needing "this device's current joined state"
    never reimplement their own slightly-different copy of it.

    ``addresses_by_family`` (``{"ipv4": ..., "ipv6": ...}``, or ``None`` if
    there's no address evidence at all) is this device's preferred address
    in each family separately - see
    :meth:`lanfence.db.DeviceStore.preferred_addresses_by_family_for_macs`.
    """

    addresses_by_family = addresses_by_family or {}
    return device.model_copy(
        update={
            "allowlisted": allow_entry is not None,
            "allowlist_name": allow_entry.name if allow_entry else None,
            "review_state": review.state,
            "review_notes": review.notes,
            "snoozed_until": review.snoozed_until,
            "presence_policy": presence.policy,
            "offline_after_seconds": presence.offline_after_seconds,
            "metadata": metadata,
            "ipv4": addresses_by_family.get("ipv4"),
            "ipv6": addresses_by_family.get("ipv6"),
        }
    )


def build_inventory(store: DeviceStore, allowlist: Allowlist) -> list[Device]:
    """Every previously observed device, with current allowlist/review/
    presence/metadata state joined in. Does not perform a scan - purely a
    database read.

    Metadata and per-family preferred addresses are each fetched in one
    bulk query for the whole inventory (see
    :meth:`lanfence.db.DeviceStore.device_metadata_for_macs`/
    ``preferred_addresses_by_family_for_macs``) rather than one query per
    device, since a device list can be large and both are shown for every
    row.
    """

    devices = store.all_devices()
    macs = [d.mac for d in devices]
    metadata_by_mac = store.device_metadata_for_macs(macs)
    addresses_by_mac = store.preferred_addresses_by_family_for_macs(macs)
    return [
        _join_device_context(
            device,
            review=store.get_review(device.mac),
            presence=store.get_presence(device.mac),
            metadata=metadata_by_mac.get(device.mac) or DeviceMetadata(mac=device.mac),
            allow_entry=allowlist.match(device.mac),
            addresses_by_family=addresses_by_mac.get(device.mac),
        )
        for device in devices
    ]


def build_device(store: DeviceStore, allowlist: Allowlist, mac: str) -> Device | None:
    """The single-device equivalent of :func:`build_inventory` - the same
    allowlist/review/presence/metadata join, for exactly one MAC. ``None``
    if this MAC has never been observed. Used by `lanfence device`/
    `review`/`allow` (and :mod:`lanfence.dossier`) so each doesn't
    reimplement this join separately - see :func:`_join_device_context`.
    """

    mac = normalize_mac(mac)
    raw_device = store.get_device(mac)
    if raw_device is None:
        return None
    addresses_by_mac = store.preferred_addresses_by_family_for_macs([mac])
    return _join_device_context(
        raw_device,
        review=store.get_review(mac),
        presence=store.get_presence(mac),
        metadata=store.get_device_metadata(mac),
        allow_entry=allowlist.match(mac),
        addresses_by_family=addresses_by_mac.get(mac),
    )


def enrich_missing_hostnames(devices: list[Device], *, resolve: bool, timeout: float) -> list[Device]:
    """Best-effort, on-demand reverse-DNS lookup for any device in
    ``devices`` that has no hostname yet - so a device doesn't sit at
    "[unknown]" forever in a listing/digest just because its one lookup
    attempt at scan time failed (a DNS server was briefly unreachable,
    the device hadn't registered its name yet, ...). Used by `lanfence
    device` and `lanfence digest`.

    Deliberately scoped and bounded:

    - **Only currently-*online* devices.** An offline device's last-known
      IP may since have been reassigned by DHCP to a different device, so
      a fresh lookup on it could return *someone else's* hostname -
      actively misleading, not just unhelpful, so it's skipped entirely
      rather than risk that.
    - **Never persisted.** This is a read command's on-the-fly display
      enrichment, not a new observation - it does not write to the
      database (unlike ``scan``/``monitor``, which persist a resolved
      name as real evidence). A resolved name here is re-attempted fresh
      every time this runs, which is the safe (if slightly wasteful)
      trade against silently mutating state from what's documented
      everywhere else as a pure read.
    - **Respects ``resolve``** (``scan.resolve_hostnames``) - if hostname
      resolution is disabled in config, this does nothing, the same as
      at scan time; it never overrides an explicit "no DNS lookups"
      choice.

    Returns a new list; ``devices`` itself is never mutated.
    """

    if not resolve:
        return devices
    updated = []
    for device in devices:
        if device.hostname or device.status != "online" or not device.ip:
            updated.append(device)
            continue
        hostname = scanner.resolve_hostname(device.ip, timeout=timeout)
        updated.append(device.model_copy(update={"hostname": hostname}) if hostname else device)
    return updated


def is_review_needed(device: Device, *, now: datetime) -> bool:
    """Untrusted, not actively snoozed, and not already flagged for
    investigation. An expired snooze (``snoozed_until`` in the past) does not
    count as active, so the device is back in the review queue."""

    if device.allowlisted or device.review_state == "investigating":
        return False
    if device.review_state == "snoozed" and device.snoozed_until is not None and device.snoozed_until > now:
        return False
    return True
