# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Console rendering and exit-code mapping for scan results."""

from __future__ import annotations

from datetime import datetime

from lanfence.models import Device, DeviceEvent, Finding, ScanResult

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


def render_findings(findings: list[Finding], *, plain: bool = False) -> str:
    """Standalone findings rendering (no device table) - used by `report`."""

    lines = [f"Findings: {len(findings)}"]
    for finding in findings:
        lines.append(f"  [{finding.severity.upper()}] {finding.title} (mac={finding.mac})")
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
        console.print(f"    MAC: {finding.mac}")
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
        lines.append(f"  [{finding.severity.upper()}] {finding.title} (mac={finding.mac})")
        if finding.rationale:
            lines.append(f"      {finding.rationale}")
        if finding.recommendation:
            lines.append(f"      Recommendation: {finding.recommendation}")

    lines.append("")
    lines.append(f"Highest severity: {result.highest_severity or 'none'}")
    return lines


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
    default_offline_after_seconds: float | None = None,
) -> str:
    """Render the ``lanfence devices`` listing - no scan, a pure database read.

    ``total_count`` (the unfiltered database size, if filters were applied)
    lets the empty case say whether the database itself is empty or a filter
    just matched nothing - passing ``None`` treats ``devices`` as unfiltered.
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
        lines.append(
            f"  - {d.mac}  {d.ip or '-':<15}  {d.hostname or '[unknown]':<24}  "
            f"{d.vendor or '[unknown]':<20}  {d.status:<8}  {trust:<20}  "
            f"{review_status_label(d, now=now):<28}  {presence:<28}  "
            f"{d.last_seen.isoformat(timespec='seconds')}"
        )
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
    table.add_column("Last seen")
    for d in devices:
        table.add_row(
            d.mac,
            d.ip or "-",
            _rich_escape(d.hostname or "[unknown]"),
            _rich_escape(d.vendor or "[unknown]"),
            d.status,
            f"yes ({_rich_escape(d.allowlist_name)})" if d.allowlisted else "no",
            _rich_escape(review_status_label(d, now=now)),
            _rich_escape(_presence_value(d, default_offline_after_seconds=default_offline_after_seconds)),
            d.last_seen.isoformat(timespec="seconds"),
        )
    console.print(table)
    return text


def render_device_detail(
    device: Device, events: list[DeviceEvent], since: datetime, *, now: datetime, plain: bool = False,
    default_offline_after_seconds: float | None = None,
) -> str:
    """Render ``lanfence device <mac>`` - current details, then the separate,
    necessarily-incomplete lifecycle timeline (see :meth:`DeviceStore.events_for`)."""

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
    return text
