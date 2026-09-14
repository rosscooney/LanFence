# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Console rendering and exit-code mapping for scan results."""

from __future__ import annotations

from datetime import datetime, timedelta

from lanfence.classify import DeviceClassification
from lanfence.dossier import DeviceDossier, TriageSummary
from lanfence.models import (
    AddressEvidence,
    AdvertisedService,
    Device,
    DeviceEvent,
    DeviceMetadata,
    Digest,
    DigestSection,
    Finding,
    InspectionResult,
    NameEvidence,
    ScanResult,
)

try:  # rich ships with typer, but keep rendering optional
    from rich.console import Console
    from rich.markup import escape as _rich_escape
    from rich.panel import Panel
    from rich.table import Table

    _RICH = True
except ImportError:  # pragma: no cover
    _RICH = False

    def _rich_escape(value: str) -> str:  # type: ignore[misc]
        return value


_SEVERITY_STYLE = {"high": "bold red", "medium": "yellow", "info": "dim"}

SEVERITY_EXIT_CODES = {None: 0, "info": 0, "medium": 10, "high": 20}


def highest_severity(findings: list[Finding]) -> str | None:
    for sev in ("high", "medium", "info"):
        if any(f.severity == sev for f in findings):
            return sev
    return None


def exit_code_for(result: ScanResult) -> int:
    return SEVERITY_EXIT_CODES.get(result.highest_severity, 0)


def exit_code_for_findings(findings: list[Finding]) -> int:
    return SEVERITY_EXIT_CODES.get(highest_severity(findings), 0)


def _finding_subject(finding: Finding) -> str:
    """A finding's identity for display - its MAC for an ordinary device
    finding, or its ``subject_id`` for one that isn't about any single
    device (e.g. an unexpected DHCP server, scoped by interface/server
    identifier)."""

    return finding.mac or finding.subject_id or "[no device]"


def render_findings(findings: list[Finding], *, plain: bool = False) -> str:
    """Standalone findings rendering (no device table) - used by `report`."""

    lines = [f"Findings: {len(findings)}"]
    for finding in findings:
        lines.append(f"  [{finding.severity.upper()}] {finding.title} (mac={_finding_subject(finding)})")
        if finding.rationale:
            lines.append(f"      {finding.rationale}")
        if finding.recommendation:
            lines.append(f"      Recommendation: {finding.recommendation}")
    text = "\n".join(lines)
    if plain or not _RICH:
        print(text)
        return text

    console = Console()
    _render_findings(console, findings)
    return text


def render_scan_result(result: ScanResult, *, plain: bool = False) -> str:
    lines = _plain_summary(result)
    text = "\n".join(lines)
    if plain or not _RICH:
        print(text)
        return text

    console = Console()
    if result.errors:
        for err in result.errors:
            console.print(f"[red]error:[/red] {_rich_escape(err)}")

    _render_device_table(console, result.devices)
    _render_findings(console, result.findings)

    console.print(
        f"\n[bold]Overall:[/bold] {len(result.findings)} finding(s), "
        f"highest severity: "
        f"[{_SEVERITY_STYLE.get(result.highest_severity or 'info', 'dim')}]"
        f"{result.highest_severity or 'none'}[/]"
    )
    return text


def _render_device_table(console, devices: list[Device]) -> None:
    if not devices:
        console.print("[yellow]No devices responded.[/yellow]")
        return
    table = Table(title=f"Devices seen ({len(devices)})")
    table.add_column("MAC")
    table.add_column("IP")
    table.add_column("Hostname", overflow="fold")
    table.add_column("Vendor", overflow="fold")
    table.add_column("Status")
    table.add_column("Trusted")
    for d in sorted(devices, key=lambda d: d.mac):
        table.add_row(
            d.mac,
            d.ip or "-",
            _rich_escape(d.hostname or "[unknown]"),
            _rich_escape(d.vendor or "[unknown]"),
            d.status,
            f"yes ({_rich_escape(d.allowlist_name)})" if d.allowlisted else "no",
        )
    console.print(table)


def _render_findings(console, findings: list[Finding]) -> None:
    if not findings:
        console.print("\n[green]No findings.[/green]")
        return
    console.print(f"\n[bold]Findings ({len(findings)})[/bold]")
    for finding in sorted(findings, key=lambda f: -{"high": 2, "medium": 1, "info": 0}[f.severity]):
        style = _SEVERITY_STYLE.get(finding.severity, "dim")
        console.print(f"\n  [{style}]{finding.severity.upper()}[/] {_rich_escape(finding.title)}")
        console.print(f"    {'MAC' if finding.mac else 'Subject'}: {_rich_escape(_finding_subject(finding))}")
        if finding.rationale:
            console.print(f"    {_rich_escape(finding.rationale.strip())}")
        if finding.recommendation:
            console.print(f"    [cyan]Recommendation:[/cyan] {_rich_escape(finding.recommendation)}")
        for line in finding.evidence:
            console.print(f"      • {_rich_escape(line)}")


def _plain_summary(result: ScanResult) -> list[str]:
    lines = [
        "LAN Fence scan result",
        f"  interface: {result.interface or '?'}",
        f"  subnet:    {result.subnet or '?'}",
        f"  started:   {result.started_at.isoformat()}",
        f"  ended:     {result.ended_at.isoformat()}",
    ]
    for err in result.errors:
        lines.append(f"  error:     {err}")

    lines.append("")
    lines.append(f"Devices seen: {len(result.devices)}")
    for d in sorted(result.devices, key=lambda d: d.mac):
        trust = f"trusted ({d.allowlist_name})" if d.allowlisted else "untrusted"
        lines.append(
            f"  - {d.mac}  {d.ip or '-':<15}  {d.hostname or '[unknown]':<24}  "
            f"{d.vendor or '[unknown]':<28}  {d.status}  {trust}"
        )

    lines.append("")
    lines.append(f"Findings: {len(result.findings)}")
    for finding in result.findings:
        lines.append(f"  [{finding.severity.upper()}] {finding.title} (mac={_finding_subject(finding)})")
        if finding.rationale:
            lines.append(f"      {finding.rationale}")
        if finding.recommendation:
            lines.append(f"      Recommendation: {finding.recommendation}")

    lines.append("")
    lines.append(f"Highest severity: {result.highest_severity or 'none'}")
    return lines


def render_triage_summary(summary: TriageSummary) -> str:
    """Orientation counts shown once after `lanfence scan`, separate from
    the compact device table (see :mod:`lanfence.dossier`'s module
    docstring) - a plain-language "what deserves a look" breakdown, never
    a numeric risk score, e.g.::

        LAN Fence has discovered 47 devices.

         31 appear straightforward
          9 need identification
          5 use private/randomised MAC addresses
          2 have higher-priority security characteristics

        None have been reviewed yet.

        Run `lanfence review` to work through them.

    Categories with a zero count are omitted rather than padded out with
    "0 ..." lines nobody needs to read. Returns "" (nothing to show) when
    ``summary.total`` is 0 - a brand-new, empty inventory.
    """

    if summary.total <= 0:
        return ""

    buckets = [
        (summary.straightforward, "appear straightforward"),
        (summary.needs_identification, "need identification"),
        (summary.private_mac, "use private/randomised MAC addresses"),
        (summary.security_flagged, "have higher-priority security characteristics"),
    ]
    buckets = [(count, label) for count, label in buckets if count > 0]
    width = max((len(str(count)) for count, _ in buckets), default=1)

    lines = [f"LAN Fence has discovered {summary.total} device{'s' if summary.total != 1 else ''}.", ""]
    lines.extend(f"{str(count).rjust(width)} {label}" for count, label in buckets)
    lines.append("")

    if summary.reviewed <= 0:
        lines.append("None have been reviewed yet.")
    elif summary.pending <= 0:
        lines.append("All devices have been reviewed.")
    else:
        lines.append(f"{summary.reviewed} of {summary.total} have been reviewed.")

    if summary.pending > 0:
        lines.append("")
        lines.append("Run `lanfence review` to work through them.")

    return "\n".join(lines)


#: Beyond this age, a persisted inspection result is labeled "stale" rather
#: than presented as current - a device's open ports/platform can easily
#: have changed since (see :mod:`lanfence.active_inspect`).
INSPECTION_STALE_AFTER = timedelta(hours=24)


def _age_label(observed_at: datetime, *, now: datetime) -> str:
    seconds = max(0.0, (now - observed_at).total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} minute(s) ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} hour(s) ago"
    return f"{int(seconds // 86400)} day(s) ago"


def render_inspection_result(result: InspectionResult, *, now: datetime) -> str:
    """The output of `lanfence inspect <mac>` - and of showing a
    previously-persisted result again. Every open port is a confirmed fact
    (the TCP handshake succeeded); every ``service``/banner label next to it
    is an *inferred* identification, never a verified capability.
    ``platform_guess`` (see :func:`lanfence.active_inspect.infer_platform`)
    is a coarse, confidence-labeled pattern match over which ports
    responded - explicitly never presented as OS fingerprinting or a
    definitive result.
    """

    age = _age_label(result.observed_at, now=now)
    stale = (now - result.observed_at) > INSPECTION_STALE_AFTER
    lines = [
        f"Active inspection of {result.mac} ({result.ip})",
        f"Method: {result.method}  ·  Observed: {result.observed_at.strftime('%d %b %Y %H:%M')} ({age})"
        + ("  [STALE - re-run for current data]" if stale else ""),
        "",
    ]

    if not result.open_ports:
        lines.append("No open ports found among the scanned ports.")
    else:
        lines.append("Confirmed open ports:")
        for p in result.open_ports:
            label = f"  {p.port}/{p.protocol}"
            if p.service:
                label += f"   inferred service: {p.service}"
            lines.append(label)

    lines.append("")
    if result.is_known_platform:
        lines.append(f"Probable platform: {result.platform_guess}")
        lines.append(f"Confidence:        {result.platform_confidence.capitalize()}")
        for reason in result.platform_reasons:
            lines.append(f"  - {reason}")
    else:
        lines.append("Probable platform: not enough evidence to guess")
    lines.append("")
    lines.append(
        "This is an inference from which ports responded, not OS fingerprinting "
        "- treat it as a hint, not a verified fact."
    )

    return "\n".join(lines)


def render_events(events: list[DeviceEvent], *, plain: bool = False) -> str:
    lines = [f"Events: {len(events)}"]
    for event in events:
        lines.append(
            f"  {event.timestamp.isoformat()}  {event.event_type:<12}  {event.mac}  "
            f"{event.ip or '-':<15}  {event.hostname or '[unknown]'}"
        )
    text = "\n".join(lines)
    if plain or not _RICH:
        print(text)
        return text

    console = Console()
    table = Table(title=f"Events ({len(events)})")
    table.add_column("Time")
    table.add_column("Event")
    table.add_column("MAC")
    table.add_column("IP")
    table.add_column("Hostname", overflow="fold")
    for event in events:
        table.add_row(
            event.timestamp.isoformat(timespec="seconds"),
            event.event_type,
            event.mac,
            event.ip or "-",
            _rich_escape(event.hostname or "[unknown]"),
        )
    console.print(table)
    return text


def review_status_label(device: Device, *, now: datetime) -> str:
    """Human display label for a device's trust/review state.

    Trust takes display precedence over any lingering review flag - a
    trusted device shows "trusted" even if it was flagged for investigation
    before being trusted. An expired snooze displays as "pending" (it no
    longer suppresses anything - see ``DeviceStore.is_snoozed``).
    """

    if device.allowlisted:
        return "trusted"
    if device.review_state == "investigating":
        return "investigating"
    if device.review_state == "snoozed" and device.snoozed_until is not None and device.snoozed_until > now:
        return f"snoozed until {device.snoozed_until.isoformat(timespec='seconds')}"
    return "pending"


def _presence_value(device: Device, *, default_offline_after_seconds: float | None = None) -> str:
    """"intermittent" / "always-on" (+ effective absence delay) / "unspecified"."""

    if device.presence_policy != "always-on" or default_offline_after_seconds is None:
        return device.presence_policy
    effective = device.offline_after_seconds or default_offline_after_seconds
    return f"always-on (alert after {effective:.0f}s absent)"


def presence_label(device: Device, *, default_offline_after_seconds: float | None = None) -> str:
    """Human display label for a device's presence policy (see
    :data:`lanfence.models.PresencePolicyName`) - "Presence: intermittent",
    "Presence: always-on", or "Presence: unspecified". For an always-on
    device, also shows the effective absence-alert delay (its own
    ``--offline-after`` override, or the global default when given)."""

    return f"Presence: {_presence_value(device, default_offline_after_seconds=default_offline_after_seconds)}"


def render_device_inventory(
    devices: list[Device], *, now: datetime, total_count: int | None = None, plain: bool = False,
    default_offline_after_seconds: float | None = None, show_metadata: bool = False,
) -> str:
    """Render the ``lanfence devices`` listing - no scan, a pure database read.

    ``total_count`` (the unfiltered database size, if filters were applied)
    lets the empty case say whether the database itself is empty or a filter
    just matched nothing - passing ``None`` treats ``devices`` as unfiltered.

    ``show_metadata`` adds owner/purpose/group/location columns - kept
    opt-in so the default table stays compact for operators who don't use
    those fields.
    """

    empty_message = (
        "No devices in the database yet - run `lanfence scan` first."
        if not total_count
        else "No devices match those filters."
    )

    lines = [f"Devices: {len(devices)}"]
    for d in devices:
        trust = f"trusted ({d.allowlist_name})" if d.allowlisted else "untrusted"
        presence = _presence_value(d, default_offline_after_seconds=default_offline_after_seconds)
        line = (
            f"  - {d.mac}  {d.ip or '-':<15}  {d.hostname or '[unknown]':<24}  "
            f"{d.vendor or '[unknown]':<20}  {d.status:<8}  {trust:<20}  "
            f"{review_status_label(d, now=now):<28}  {presence:<28}  "
            f"{d.last_seen.isoformat(timespec='seconds')}"
        )
        if show_metadata:
            m = d.metadata or DeviceMetadata(mac=d.mac)
            line += (
                f"  owner={m.owner or '-'}  purpose={m.purpose or '-'}  "
                f"group={m.group or '-'}  location={m.location or '-'}"
            )
        lines.append(line)
    text = "\n".join(lines)
    if plain or not _RICH:
        print(text)
        return text

    console = Console()
    if not devices:
        console.print(f"[yellow]{empty_message}[/yellow]")
        return text

    table = Table(title=f"Devices ({len(devices)})")
    table.add_column("MAC")
    table.add_column("IP")
    table.add_column("Hostname", overflow="fold")
    table.add_column("Vendor", overflow="fold")
    table.add_column("Status")
    table.add_column("Trusted")
    table.add_column("Review")
    table.add_column("Presence")
    if show_metadata:
        table.add_column("Owner", overflow="fold")
        table.add_column("Purpose", overflow="fold")
        table.add_column("Group", overflow="fold")
        table.add_column("Location", overflow="fold")
    table.add_column("Last seen")
    for d in devices:
        row = [
            d.mac,
            d.ip or "-",
            _rich_escape(d.hostname or "[unknown]"),
            _rich_escape(d.vendor or "[unknown]"),
            d.status,
            f"yes ({_rich_escape(d.allowlist_name)})" if d.allowlisted else "no",
            _rich_escape(review_status_label(d, now=now)),
            _rich_escape(_presence_value(d, default_offline_after_seconds=default_offline_after_seconds)),
        ]
        if show_metadata:
            m = d.metadata or DeviceMetadata(mac=d.mac)
            row.extend(
                [
                    _rich_escape(m.owner or "-"),
                    _rich_escape(m.purpose or "-"),
                    _rich_escape(m.group or "-"),
                    _rich_escape(m.location or "-"),
                ]
            )
        row.append(d.last_seen.isoformat(timespec="seconds"))
        table.add_row(*row)
    console.print(table)
    return text


def _classification_lines(classification: DeviceClassification, *, escape: bool = False) -> list[str]:
    """Plain-text "Likely device" block shared by `render_device_detail`
    and the compact review-queue dossier - a conservative, confidence-
    labeled guess, never presented as fact. ``escape`` applies Rich markup
    escaping for the rich-console render path."""

    esc = _rich_escape if escape else (lambda s: s)
    if not classification.is_known:
        return [f"Likely device: {esc(classification.device_type)} (no supporting evidence)"]
    lines = [
        f"Likely device: {esc(classification.device_type)}",
        f"Confidence:    {classification.confidence.capitalize()}",
    ]
    for reason in classification.reasons:
        lines.append(f"  - {esc(reason)}")
    return lines


def _dossier_evidence_lines(dossier: DeviceDossier) -> list[str]:
    """Short, source-labeled evidence bullets for the compact review
    dossier - each traces to a specific retained observation (never a
    fabricated claim); see :meth:`DeviceDossier.observed_services_summary`
    for the separate "what does it advertise" list."""

    lines: list[str] = []
    for name in dossier.names:
        if name.source == "dhcp_option_12":
            lines.append(f"DHCP hostname: {name.name}")
        elif name.source == "reverse_dns":
            lines.append(f"Reverse DNS: {name.name}")
    for service in dossier.services:
        if service.status != "current":
            continue
        if service.protocol == "mdns" and service.instance_name:
            lines.append(f"mDNS: {service.instance_name}")
        elif service.protocol == "ssdp" and service.server:
            lines.append(f"SSDP server (advertised claim): {service.server}")
    if dossier.device.vendor:
        lines.append(f"OUI: {dossier.device.vendor}")
    if dossier.is_locally_administered_mac:
        lines.append("MAC is locally administered (randomized or manually set) - no vendor to identify")
    return lines


def render_dossier_compact(
    dossier: DeviceDossier, *, index: int | None = None, total: int | None = None,
    priority_label: str | None = None,
) -> str:
    """The compact per-device view shown by the interactive `lanfence
    review` queue before asking what to do - progressive disclosure over
    :func:`render_device_detail`'s full report: just enough to answer "what
    is this, and does it deserve a closer look" (see
    :meth:`DeviceDossier.label` for the name preference, and
    :mod:`lanfence.classify` for the classification's own caveats).
    ``index``/``total`` (1-based) add a "Device N of M" header when given;
    ``priority_label`` (see :func:`lanfence.dossier.review_priority`) is
    shown alongside it, not as a numeric score.
    """

    lines: list[str] = []
    if index is not None and total is not None:
        header = f"Device {index} of {total}"
        if priority_label:
            header += f"  ·  {priority_label}"
        lines.append(header)
        lines.append("─" * max(len(header), 24))
        lines.append("")

    lines.append(dossier.label)
    if dossier.device.ip:
        lines.append(dossier.device.ip)
    if dossier.device.vendor:
        lines.append(dossier.device.vendor)

    lines.append("")
    lines.extend(_classification_lines(dossier.classification))

    lines.append("")
    lines.append(f"First seen: {dossier.device.first_seen.strftime('%d %b %Y %H:%M')}")
    lines.append(f"Last seen:  {dossier.device.last_seen.strftime('%d %b %Y %H:%M')}")
    lines.append(f"Status:     {dossier.device.status.capitalize()}")

    services = dossier.observed_services_summary
    if services:
        lines.append("")
        lines.append("Observed / advertised services:")
        lines.extend(f"  - {s}" for s in services)

    evidence = _dossier_evidence_lines(dossier)
    if evidence:
        lines.append("")
        lines.append("Evidence:")
        lines.extend(f"  - {e}" for e in evidence)

    return "\n".join(lines)


_ADDRESS_SOURCE_LABELS = {
    "arp": "ARP", "ipv6_nd": "IPv6 ND", "dhcp_ack": "DHCP (lease)", "legacy_snapshot": "legacy",
}
_NAME_SOURCE_LABELS = {
    "dhcp_option_12": "DHCP option 12", "reverse_dns": "reverse DNS", "legacy_snapshot": "legacy",
}


def _address_evidence_lines(addresses: list[AddressEvidence]) -> list[str]:
    lines = [f"Addresses ({len(addresses)} retained):"]
    if not addresses:
        lines.append("  (none)")
    for a in addresses:
        label = _ADDRESS_SOURCE_LABELS.get(a.source, a.source)
        lines.append(f"  {a.ip}")
        iface = f"  Interface: {a.interface}" if a.interface else ""
        lines.append(f"    Source: {label}{iface}")
        if a.kind == "lease_reported":
            lines.append("    (DHCP-server-reported lease - not itself proof of use)")
        lines.append(f"    First observed: {a.first_seen.isoformat(timespec='seconds')}")
        lines.append(f"    Last observed:  {a.last_seen.isoformat(timespec='seconds')}")
    return lines


def _name_evidence_lines(names: list[NameEvidence]) -> list[str]:
    lines = [f"Names ({len(names)} retained):"]
    if not names:
        lines.append("  (none)")
    for n in names:
        label = _NAME_SOURCE_LABELS.get(n.source, n.source)
        if n.source == "reverse_dns" and n.ip:
            label = f"{label} for {n.ip}"
        lines.append(f"  {n.name}")
        lines.append(f"    Source: {label}")
        lines.append(f"    First observed: {n.first_seen.isoformat(timespec='seconds')}")
        lines.append(f"    Last observed:  {n.last_seen.isoformat(timespec='seconds')}")
    return lines


_DISCOVERY_PROTOCOL_LABELS = {"mdns": "mDNS/DNS-SD", "ssdp": "SSDP/UPnP"}
_ASSOCIATION_LABELS = {
    "target_address_match": "target IP matched observed device address",
    "source_address_match": "packet source IP matched observed device address",
}


def _mdns_type_display(service_type: str) -> str:
    """``"_ipp._tcp.local"`` -> ``"_ipp._tcp"`` for a terser display - the
    stored ``service_type`` always includes the ``.local`` domain."""

    return service_type.rstrip(".").removesuffix(".local")


def _association_label(service: AdvertisedService) -> str:
    if service.mac:
        return _ASSOCIATION_LABELS.get(service.attribution_basis, "matched observed device address")
    return "unassociated - no confident device match"


def _advertised_service_lines(services: list[AdvertisedService]) -> list[str]:
    """Plain-text "Advertised services" section shared by
    ``render_device_detail`` - see the module's CLI example in the
    passive-discovery feature's README section for the exact shape."""

    lines = [f"Advertised services ({len(services)} known):"]
    if not services:
        lines.append("  (none)")
    for s in services:
        type_display = _mdns_type_display(s.service_type) if s.protocol == "mdns" else s.service_type
        header = f"{s.service_label} — {type_display}" if s.service_label else type_display
        lines.append(f"  {header}")
        if s.instance_name:
            lines.append(f"    Instance: {s.instance_name}")
        if s.target_host:
            target = f"{s.target_host}:{s.target_port}" if s.target_port else s.target_host
            lines.append(f"    Target: {target}")
        if s.protocol == "ssdp":
            if s.server:
                lines.append(f"    Server (advertised claim, unverified): {s.server}")
            if s.location:
                lines.append(f"    Location (advertised, never fetched): {s.location}")
        if s.attributes:
            attrs = ", ".join(f"{k}={v}" for k, v in s.attributes.items())
            lines.append(f"    Attributes (advertised claims, unverified): {attrs}")
        iface = f" · Interface: {s.interface}" if s.interface else ""
        lines.append(f"    Source: {_DISCOVERY_PROTOCOL_LABELS[s.protocol]}{iface}")
        lines.append(f"    Last observed: {s.last_seen.isoformat(timespec='seconds')}")
        if s.status == "withdrawn":
            lines.append("    Status: withdrawn (the advertiser explicitly announced it's gone)")
        elif s.status == "expired":
            lines.append("    Status: expired (no refresh before its advertised lifetime lapsed)")
        elif s.expires_at:
            lines.append(f"    Advertisement expires: {s.expires_at.isoformat(timespec='seconds')}")
        lines.append(f"    Association: {_association_label(s)}")
    return lines


def render_channels_table(statuses: list, *, plain: bool = False) -> str:
    """Render ``lanfence channels`` - one row per communication channel
    (see :func:`lanfence.channels.list_channel_statuses`). Never shows a
    password, token, full webhook URL, or credential-bearing path - each
    row's ``summary`` is already sanitized by the caller."""

    lines = ["Channels:"]
    for s in statuses:
        digest_col = "-" if s.digest_selected is None else ("yes" if s.digest_selected else "no")
        lines.append(
            f"  {s.channel:<10} enabled={str(s.enabled):<5} configured={str(s.configured):<5} "
            f"digest={digest_col:<3} {s.summary}"
        )
    text = "\n".join(lines)
    if plain or not _RICH:
        print(text)
        return text

    console = Console()
    table = Table(title="Channels")
    table.add_column("Channel")
    table.add_column("Enabled")
    table.add_column("Configured")
    table.add_column("Digest")
    table.add_column("Destination", overflow="fold")
    for s in statuses:
        digest_col = "-" if s.digest_selected is None else ("yes" if s.digest_selected else "no")
        table.add_row(
            s.channel,
            "[green]yes[/green]" if s.enabled else "[dim]no[/dim]",
            "[green]yes[/green]" if s.configured else "[yellow]no[/yellow]",
            digest_col,
            _rich_escape(s.summary),
        )
    console.print(table)
    return text


def render_advertised_services(
    services: list[AdvertisedService], *, now: datetime, total_count: int | None = None, plain: bool = False,
) -> str:
    """Render ``lanfence services`` - a pure database read of correlated
    advertised-service evidence (see
    :meth:`lanfence.db.DeviceStore.advertised_services`). Never scans or
    sends discovery traffic; the absence of a service here is not evidence
    it doesn't exist, only that nothing advertising it has been observed
    at this capture point yet. ``total_count`` (the unfiltered count, if
    filters were applied) distinguishes an empty database from a filter
    matching nothing - the same convention as ``render_device_inventory``.
    """

    empty_message = (
        "No advertised services observed yet - mDNS/SSDP discovery may be disabled "
        "(see `discovery.mdns`/`discovery.ssdp`), or nothing advertising a recognized service has "
        "been seen at this capture point. Absence of evidence is not evidence of absence."
        if not total_count
        else "No advertised services match those filters."
    )

    lines = [f"Advertised services: {len(services)}"]
    for s in services:
        type_display = _mdns_type_display(s.service_type) if s.protocol == "mdns" else s.service_type
        label = s.service_label or type_display
        assoc = s.mac or "unassociated"
        lines.append(
            f"  - [{s.protocol}] {label:<14} {type_display:<20} {(s.instance_name or '-'):<24} "
            f"{assoc:<20} {s.status:<10} {s.last_seen.isoformat(timespec='seconds')}"
        )
    text = "\n".join(lines)
    if plain or not _RICH:
        print(text)
        return text

    console = Console()
    if not services:
        console.print(f"[yellow]{empty_message}[/yellow]")
        return text

    table = Table(title=f"Advertised services ({len(services)})")
    table.add_column("Protocol")
    table.add_column("Service")
    table.add_column("Type", overflow="fold")
    table.add_column("Instance", overflow="fold")
    table.add_column("MAC")
    table.add_column("Status")
    table.add_column("Last seen")
    for s in services:
        type_display = _mdns_type_display(s.service_type) if s.protocol == "mdns" else s.service_type
        table.add_row(
            s.protocol,
            _rich_escape(s.service_label or "-"),
            _rich_escape(type_display),
            _rich_escape(s.instance_name or "-"),
            s.mac or "[dim]unassociated[/dim]",
            s.status,
            s.last_seen.isoformat(timespec="seconds"),
        )
    console.print(table)
    return text


def _inspection_summary_lines(inspection: InspectionResult, *, now: datetime) -> list[str]:
    age = _age_label(inspection.observed_at, now=now)
    stale = (now - inspection.observed_at) > INSPECTION_STALE_AFTER
    lines = [
        "Active inspection (see `lanfence inspect` for a probe-by-probe breakdown):",
        f"  Observed: {inspection.observed_at.strftime('%d %b %Y %H:%M')} ({age})"
        + ("  [STALE - re-run for current data]" if stale else ""),
    ]
    if inspection.open_ports:
        ports = ", ".join(f"{p.port}/{p.protocol}" for p in inspection.open_ports)
        lines.append(f"  Confirmed open ports: {ports}")
    else:
        lines.append("  Confirmed open ports: none found among the scanned ports")
    if inspection.is_known_platform:
        lines.append(f"  Probable platform: {inspection.platform_guess} (confidence: {inspection.platform_confidence})")
    return lines


def render_device_detail(
    device: Device, events: list[DeviceEvent], since: datetime, *, now: datetime, plain: bool = False,
    default_offline_after_seconds: float | None = None,
    addresses: list[AddressEvidence] | None = None, names: list[NameEvidence] | None = None,
    services: list[AdvertisedService] | None = None,
    classification: DeviceClassification | None = None,
    inspection: InspectionResult | None = None,
) -> str:
    """Render ``lanfence device <mac>`` - current (preferred) details, all
    retained address/name evidence, advertised-service evidence, then the
    separate, necessarily-incomplete lifecycle timeline (see
    :meth:`DeviceStore.events_for`).

    ``addresses``/``names`` are retained evidence *summaries* (first/last
    observed), not a complete history of continuous assignment - an older
    entry does not mean that address/name was released or replaced, only
    that nothing has re-confirmed it recently. Omit either (``None``) to
    skip that section entirely (e.g. a caller that hasn't fetched it).
    ``services`` (see :meth:`lanfence.db.DeviceStore.advertised_services`)
    are device-advertised claims, never verified capabilities or proof of
    reachability - omit (``None``) the same way. ``classification`` (see
    :mod:`lanfence.classify`) is a conservative, confidence-labeled "likely
    device" guess - omit to skip that line entirely rather than show a
    misleading "Unknown device" for a caller that never computed one.
    """

    trust = f"trusted ({device.allowlist_name})" if device.allowlisted else "untrusted"
    lines = [
        f"Device {device.mac}",
        "",
        "Current details (as of the most recent sighting):",
        f"  IP:         {device.ip or '[unknown]'}",
        f"  Hostname:   {device.hostname or '[unknown]'}",
        f"  Vendor:     {device.vendor or '[unknown]'}",
        f"  Status:     {device.status}",
        f"  First seen: {device.first_seen.isoformat(timespec='seconds')}",
        f"  Last seen:  {device.last_seen.isoformat(timespec='seconds')}",
        f"  Trust:      {trust}",
        f"  Review:     {review_status_label(device, now=now)}",
        f"  {presence_label(device, default_offline_after_seconds=default_offline_after_seconds)}",
    ]
    if device.review_notes:
        lines.append(f"  Notes:      {device.review_notes}")
    if device.fingerprints:
        lines.append(f"  Fingerprint signals: {', '.join(device.fingerprints)}")

    if classification is not None:
        lines.append("")
        lines.extend(_classification_lines(classification))

    metadata = device.metadata or DeviceMetadata(mac=device.mac)
    lines.append("")
    lines.append("Inventory details (user-provided, not derived from observed traffic):")
    lines.append(f"  Owner:      {metadata.owner or 'Not set'}")
    lines.append(f"  Purpose:    {metadata.purpose or 'Not set'}")
    lines.append(f"  Group:      {metadata.group or 'Not set'}")
    lines.append(f"  Location:   {metadata.location or 'Not set'}")

    lines.append("")
    lines.append(
        f"Lifecycle timeline since {since.isoformat(timespec='seconds')} ({len(events)} event(s)):"
    )
    lines.append(
        "  Only connect/reappear/disconnect transitions are logged here - a device that stayed "
        "online the whole time may have changed IP/hostname with no entry below; this is not a "
        "complete history of every address the MAC has held."
    )
    for event in events:
        lines.append(
            f"  {event.timestamp.isoformat(timespec='seconds')}  {event.event_type:<12}  "
            f"{event.ip or '-':<15}  {event.hostname or '[unknown]'}"
        )

    if addresses is not None or names is not None:
        lines.append("")
        if addresses is not None:
            lines.extend(_address_evidence_lines(addresses))
        if names is not None:
            lines.append("")
            lines.extend(_name_evidence_lines(names))

    if services is not None:
        lines.append("")
        lines.extend(_advertised_service_lines(services))

    if inspection is not None:
        lines.append("")
        lines.extend(_inspection_summary_lines(inspection, now=now))

    text = "\n".join(lines)
    if plain or not _RICH:
        print(text)
        return text

    console = Console()
    detail_lines = [
        "[bold]Current details[/bold] (as of the most recent sighting):",
        f"IP:         {device.ip or '[unknown]'}",
        f"Hostname:   {_rich_escape(device.hostname or '[unknown]')}",
        f"Vendor:     {_rich_escape(device.vendor or '[unknown]')}",
        f"Status:     {device.status}",
        f"First seen: {device.first_seen.isoformat(timespec='seconds')}",
        f"Last seen:  {device.last_seen.isoformat(timespec='seconds')}",
        f"Trust:      {_rich_escape(trust)}",
        f"Review:     {_rich_escape(review_status_label(device, now=now))}",
        _rich_escape(presence_label(device, default_offline_after_seconds=default_offline_after_seconds)),
    ]
    if device.review_notes:
        detail_lines.append(f"Notes:      {_rich_escape(device.review_notes)}")
    if device.fingerprints:
        detail_lines.append(f"Fingerprint signals: {_rich_escape(', '.join(device.fingerprints))}")
    console.print(Panel("\n".join(detail_lines), title=f"Device {device.mac}"))

    if classification is not None:
        console.print(Panel("\n".join(_classification_lines(classification, escape=True)), title="Likely device"))

    console.print(
        Panel(
            "\n".join(
                [
                    f"Owner:      {_rich_escape(metadata.owner or 'Not set')}",
                    f"Purpose:    {_rich_escape(metadata.purpose or 'Not set')}",
                    f"Group:      {_rich_escape(metadata.group or 'Not set')}",
                    f"Location:   {_rich_escape(metadata.location or 'Not set')}",
                ]
            ),
            title="Inventory details (user-provided)",
        )
    )

    if inspection is not None:
        console.print(Panel("\n".join(_inspection_summary_lines(inspection, now=now)), title="Active inspection"))

    console.print(
        f"\n[bold]Lifecycle timeline[/bold] since {since.isoformat(timespec='seconds')} "
        f"({len(events)} event(s))"
    )
    console.print(
        "[dim]Only connect/reappear/disconnect transitions are logged - a device that stayed "
        "online throughout may have changed IP/hostname with no entry below; this is not a "
        "complete history of every address the MAC has held.[/dim]"
    )
    if events:
        table = Table()
        table.add_column("Time")
        table.add_column("Event")
        table.add_column("IP")
        table.add_column("Hostname", overflow="fold")
        for event in events:
            table.add_row(
                event.timestamp.isoformat(timespec="seconds"),
                event.event_type,
                event.ip or "-",
                _rich_escape(event.hostname or "[unknown]"),
            )
        console.print(table)
    else:
        console.print("[dim](no events in this window)[/dim]")

    if addresses is not None:
        console.print(f"\n[bold]Addresses[/bold] ({len(addresses)} retained)")
        if not addresses:
            console.print("[dim](none)[/dim]")
        for a in addresses:
            label = _ADDRESS_SOURCE_LABELS.get(a.source, a.source)
            iface = f" · Interface: {_rich_escape(a.interface)}" if a.interface else ""
            lease_note = " [dim](DHCP-reported lease - not itself proof of use)[/dim]" if a.kind == "lease_reported" else ""
            console.print(f"  [bold]{_rich_escape(a.ip)}[/bold]")
            console.print(f"    Source: {label}{iface}{lease_note}")
            console.print(
                f"    First observed: {a.first_seen.isoformat(timespec='seconds')}   "
                f"Last observed: {a.last_seen.isoformat(timespec='seconds')}"
            )

    if names is not None:
        console.print(f"\n[bold]Names[/bold] ({len(names)} retained)")
        if not names:
            console.print("[dim](none)[/dim]")
        for n in names:
            label = _NAME_SOURCE_LABELS.get(n.source, n.source)
            if n.source == "reverse_dns" and n.ip:
                label = f"{label} for {n.ip}"
            console.print(f"  [bold]{_rich_escape(n.name)}[/bold]")
            console.print(f"    Source: {label}")
            console.print(
                f"    First observed: {n.first_seen.isoformat(timespec='seconds')}   "
                f"Last observed: {n.last_seen.isoformat(timespec='seconds')}"
            )

    if services is not None:
        console.print(f"\n[bold]Advertised services[/bold] ({len(services)} known)")
        if not services:
            console.print("[dim](none)[/dim]")
        for s in services:
            type_display = _mdns_type_display(s.service_type) if s.protocol == "mdns" else s.service_type
            header = f"{s.service_label} — {type_display}" if s.service_label else type_display
            console.print(f"  [bold]{_rich_escape(header)}[/bold]")
            if s.instance_name:
                console.print(f"    Instance: {_rich_escape(s.instance_name)}")
            if s.target_host:
                target = f"{s.target_host}:{s.target_port}" if s.target_port else s.target_host
                console.print(f"    Target: {_rich_escape(target)}")
            if s.protocol == "ssdp":
                if s.server:
                    console.print(f"    Server (advertised claim, unverified): {_rich_escape(s.server)}")
                if s.location:
                    console.print(f"    Location (advertised, never fetched): {_rich_escape(s.location)}")
            if s.attributes:
                attrs = ", ".join(f"{k}={v}" for k, v in s.attributes.items())
                console.print(f"    Attributes (advertised claims, unverified): {_rich_escape(attrs)}")
            iface = f" · Interface: {_rich_escape(s.interface)}" if s.interface else ""
            console.print(f"    Source: {_DISCOVERY_PROTOCOL_LABELS[s.protocol]}{iface}")
            console.print(f"    Last observed: {s.last_seen.isoformat(timespec='seconds')}")
            if s.status == "withdrawn":
                console.print("    Status: [yellow]withdrawn[/yellow] (the advertiser announced it's gone)")
            elif s.status == "expired":
                console.print("    Status: [yellow]expired[/yellow] (no refresh before its lifetime lapsed)")
            elif s.expires_at:
                console.print(f"    Advertisement expires: {s.expires_at.isoformat(timespec='seconds')}")
            console.print(f"    Association: {_rich_escape(_association_label(s))}")

    return text


def _section_lines(title: str, section: DigestSection) -> list[str]:
    lines = [f"{title} ({section.total_count}):"]
    if not section.items:
        lines.append("  (none)")
    for entry in section.items:
        label = entry.name or entry.mac
        context = ""
        if entry.owner or entry.group:
            bits = [b for b in (entry.owner, entry.group) if b]
            context = f"  ({', '.join(bits)})"
        line = f"  - {label} ({entry.mac})  {entry.ip or '-':<15}  {entry.hostname or '[unknown]'}{context}"
        if entry.services_summary:
            line += f"  advertises: {entry.services_summary}"
        lines.append(line)
    if section.omitted_count:
        lines.append(f"  ... and {section.omitted_count} more")
    return lines


def render_digest(digest: Digest, *, plain: bool = False) -> str:
    """Render `lanfence digest` - a preview of :func:`lanfence.digest.build_digest`'s
    output. Never scans or mutates anything; a pure display of one already-built
    :class:`~lanfence.models.Digest`."""

    lines = [
        f"LAN Fence digest - {digest.window_start.isoformat(timespec='seconds')} "
        f"to {digest.window_end.isoformat(timespec='seconds')}",
        f"Generated: {digest.generated_at.isoformat(timespec='seconds')}",
        "",
        f"Known devices: {digest.known_devices}   Online now: {digest.online_devices}",
        f"New in window: {digest.activity.new_device_count}   "
        f"Reappeared: {digest.activity.reappeared_device_count}   "
        f"Disconnected: {digest.activity.disconnected_device_count}",
        f"Needs review: {digest.needs_review.total_count}   "
        f"Investigating: {digest.investigating.total_count}   "
        f"Missing always-on: {digest.missing_always_on.total_count}",
        digest.monitoring_health,
        "",
    ]
    lines += _section_lines("New devices", digest.new_devices)
    lines.append("")
    lines += _section_lines("Needs review", digest.needs_review)
    lines.append("")
    lines += _section_lines("Investigating", digest.investigating)
    lines.append("")
    lines += _section_lines("Missing always-on devices", digest.missing_always_on)

    text = "\n".join(lines)
    if plain or not _RICH:
        print(text)
        return text

    console = Console()
    console.print(f"[bold]LAN Fence digest[/bold] - {digest.window_start.isoformat(timespec='seconds')} "
                  f"to {digest.window_end.isoformat(timespec='seconds')}")
    console.print(f"[dim]Generated: {digest.generated_at.isoformat(timespec='seconds')}[/dim]")
    console.print(
        f"Known devices: {digest.known_devices}   Online now: {digest.online_devices}   "
        f"[dim]{_rich_escape(digest.monitoring_health)}[/dim]"
    )
    console.print(
        f"New: {digest.activity.new_device_count}   Reappeared: {digest.activity.reappeared_device_count}   "
        f"Disconnected: {digest.activity.disconnected_device_count}   "
        f"Needs review: {digest.needs_review.total_count}   "
        f"Investigating: {digest.investigating.total_count}   "
        f"Missing always-on: {digest.missing_always_on.total_count}"
    )

    for title, section in (
        ("New devices", digest.new_devices),
        ("Needs review", digest.needs_review),
        ("Investigating", digest.investigating),
        ("Missing always-on devices", digest.missing_always_on),
    ):
        if not section.items:
            console.print(f"\n[dim]{title}: none[/dim]")
            continue
        show_services = title == "New devices"
        table = Table(title=f"{title} ({section.total_count})")
        table.add_column("MAC")
        table.add_column("Name")
        table.add_column("IP")
        table.add_column("Hostname", overflow="fold")
        table.add_column("Owner", overflow="fold")
        table.add_column("Group", overflow="fold")
        if show_services:
            table.add_column("Advertises", overflow="fold")
        for entry in section.items:
            row = [
                entry.mac, _rich_escape(entry.name or "-"), entry.ip or "-",
                _rich_escape(entry.hostname or "[unknown]"),
                _rich_escape(entry.owner or "-"), _rich_escape(entry.group or "-"),
            ]
            if show_services:
                row.append(_rich_escape(entry.services_summary or "-"))
            table.add_row(*row)
        console.print(table)
        if section.omitted_count:
            console.print(f"[dim]... and {section.omitted_count} more[/dim]")

    return text
