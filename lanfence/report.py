# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Console rendering and exit-code mapping for scan results."""

from __future__ import annotations

from lanfence.models import Device, DeviceEvent, Finding, ScanResult

try:  # rich ships with typer, but keep rendering optional
    from rich.console import Console
    from rich.markup import escape as _rich_escape
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
