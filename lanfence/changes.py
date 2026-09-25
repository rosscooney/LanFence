# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Know When It Changes: the plain-language side of change events.

A :class:`~lanfence.models.ChangeEvent` stores *what* changed as structured
data (see :mod:`lanfence.baseline`, which records them). This module turns
that data into words an administrator can act on - "New service detected:
SSH / TCP 22" rather than ``tcp/22 0->1`` - and is the one place every
surface (CLI, web, digest, alerts) gets that wording from, so they never
drift apart.

Wording rule: say exactly what was observed, never that something is
malicious. A change is evidence, not proof of compromise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from lanfence.discovery import WELL_KNOWN_MDNS_LABELS
from lanfence.models import SIGNIFICANCES, ChangeEvent

#: Friendly names for well-known TCP ports. A port not listed is shown by
#: number alone - never guessed at.
PORT_NAMES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 135: "MS RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 548: "AFP", 554: "RTSP", 631: "IPP printing",
    2222: "SSH (alternate port)", 2375: "Docker API", 2376: "Docker API (TLS)", 3389: "RDP",
    5000: "Web admin (5000)", 5001: "Web admin (5001)", 5900: "VNC", 5901: "VNC", 5985: "WinRM",
    5986: "WinRM (HTTPS)", 8080: "HTTP (alternate port)", 8291: "MikroTik Winbox", 8443: "HTTPS (alternate port)",
    9100: "Printer (JetDirect)", 10000: "Webmin", 62078: "Apple device sync",
}

#: Remote-administration services - the ones a new appearance of always
#: deserves a look, and which are never absorbed into a baseline silently
#: (see :mod:`lanfence.baseline`).
ADMIN_PORTS: frozenset[int] = frozenset({22, 23, 2222, 2375, 2376, 3389, 5900, 5901, 5985, 5986, 8291, 10000})
ADMIN_MDNS_TYPES: dict[str, str] = {
    "_ssh._tcp": "SSH",
    "_sftp-ssh._tcp": "SFTP (SSH)",
    "_telnet._tcp": "Telnet",
    "_rfb._tcp": "VNC screen sharing",
    "_rdp._tcp": "Remote Desktop",
}


def normalize_mdns_type(service_type: str) -> str:
    """``"_SSH._tcp.local."`` -> ``"_ssh._tcp"``: the stable key a baseline
    tracks, independent of case and domain."""

    value = service_type.strip().lower().rstrip(".")
    if value.endswith(".local"):
        value = value[: -len(".local")]
    return value


def port_value(port: int, protocol: str = "tcp") -> str:
    return f"{protocol}/{port}"


def _port_number(value: str) -> int | None:
    try:
        return int(value.split("/", 1)[1])
    except (IndexError, ValueError):
        return None


def is_admin_service(signal: str | None, value: str | None) -> bool:
    if value is None:
        return False
    if signal == "port":
        return _port_number(value) in ADMIN_PORTS
    if signal == "mdns":
        return value in ADMIN_MDNS_TYPES
    return False


def service_label(signal: str | None, value: str | None) -> str:
    """How one baseline item reads to a person, e.g. "SSH / TCP 22"."""

    if value is None:
        return "?"
    if signal == "port":
        number = _port_number(value)
        protocol = value.split("/", 1)[0].upper()
        name = PORT_NAMES.get(number) if number is not None else None
        return f"{name} / {protocol} {number}" if name else f"{protocol} {number}"
    if signal == "mdns":
        name = ADMIN_MDNS_TYPES.get(value) or WELL_KNOWN_MDNS_LABELS.get(value)
        return f"{name} (mDNS {value})" if name else f"mDNS {value}"
    if signal == "ssdp":
        return f"UPnP {value}"
    if signal == "ipv6_prefix":
        return f"IPv6 network {value}"
    return value


def significance_label(significance: str) -> str:
    return significance.upper()


def significance_at_least(significance: str, threshold: str) -> bool:
    return SIGNIFICANCES.index(significance) >= SIGNIFICANCES.index(threshold)


def _days(value: object) -> str:
    try:
        days = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ""
    if days < 1:
        return "less than a day"
    whole = int(days)
    return f"{whole} day" if whole == 1 else f"{whole} days"


@dataclass(frozen=True)
class ChangeDescription:
    """A change in words: a one-line ``title`` and supporting ``details``
    (what it was before, how long LAN Fence has been watching)."""

    title: str
    details: list[str] = field(default_factory=list)


def describe(event: ChangeEvent) -> ChangeDescription:
    """The plain-language title and detail lines for one change."""

    prev, cur = event.previous, event.current
    kind = event.change_type
    label = service_label(event.signal, event.subject)
    details: list[str] = []

    if kind == "new_device":
        title = "New device joined"
    elif kind == "reappeared":
        away = cur.get("absent_days")
        title = f"Device returned after {_days(away)} away" if away is not None and float(away) >= 1 else (
            "Device returned"
        )
    elif kind == "disconnected":
        title = "Always-on device went offline" if cur.get("presence") == "always-on" else "Device went offline"
    elif kind == "ip_changed":
        title = f"IP address changed: {prev.get('ipv4')} -> {cur.get('ipv4')}"
        if cur.get("different_network"):
            details.append("The new address is on a different network from the old one.")
        else:
            details.append("An address change within the same network is usually routine DHCP reassignment.")
    elif kind == "ipv6_prefix_new":
        title = f"New IPv6 network observed: {event.subject}"
        details.append("Individual IPv6 addresses change routinely for privacy; this is a new network prefix.")
    elif kind == "hostname_changed":
        title = f"Hostname changed: {prev.get('hostname')} -> {cur.get('hostname')}"
    elif kind == "identity_changed":
        title = (
            f"Identity changed: {prev.get('identity') or 'unknown'} -> {cur.get('identity') or 'unknown'}"
        )
        details.append(
            "LAN Fence now identifies this device differently from before. Identity is inferred, so this "
            "may reflect new evidence rather than a different device - but it's worth confirming."
        )
    elif kind == "trust_changed":
        title = f"Trusted as {cur.get('name')!r}" if cur.get("trusted") else "No longer trusted"
    elif kind in ("service_new", "mdns_service_new", "ssdp_service_new"):
        noun = {"service_new": "service", "mdns_service_new": "advertised service",
                "ssdp_service_new": "UPnP capability"}[kind]
        title = f"New {noun} detected: {label}"
        baseline = cur.get("baseline")
        if baseline is not None:
            details.append(f"Previous baseline: {', '.join(baseline) if baseline else 'nothing of this kind'}")
        monitored = cur.get("monitored_days")
        if cur.get("established") and monitored is not None:
            details.append(
                f"{label.split(' (')[0].split(' / ')[0]} has not been part of this device's baseline "
                f"during {_days(monitored)} of monitoring."
            )
        elif cur.get("learning"):
            details.append(
                "This device's baseline is still being learned, but remote-administration services are "
                "never added to a baseline without your approval."
            )
        if cur.get("returned"):
            details.append("It had been seen before, went away, and has now come back.")
    elif kind in ("service_removed", "mdns_service_removed", "ssdp_service_removed"):
        noun = {"service_removed": "Service", "mdns_service_removed": "Advertised service",
                "ssdp_service_removed": "UPnP capability"}[kind]
        title = f"{noun} no longer detected: {label}"
        if cur.get("was_baseline"):
            details.append("It was part of this device's established baseline.")
    elif kind == "baseline_established":
        title = f"Baseline established after {_days(cur.get('learning_days'))} of learning"
        details.append("From now on, new services on this device are flagged for review instead of learned.")
    elif kind == "baseline_reset":
        title = "Baseline reset - learning again"
    elif kind == "unknown_device_present":
        title = f"Unknown device still on the network after {int(cur.get('minutes', 0))} minutes"
        details.append("It isn't trusted and hasn't been reviewed.")
    elif kind == "dhcp_server_unexpected":
        title = f"Unapproved DHCP server: {cur.get('server_id')} on {cur.get('interface')}"
        details.append(
            "A DHCP server not on your approved list answered on this network. It may be a misconfigured "
            "device, a backup server, or something that deserves investigation."
        )
    elif kind == "risk_changed":
        title = (
            f"Risk changed: {str(prev.get('level', '?')).upper()} {prev.get('score', '?')} -> "
            f"{str(cur.get('level', '?')).upper()} {cur.get('score', '?')}"
        )
    else:
        title = kind.replace("_", " ").capitalize()

    return ChangeDescription(title=title, details=details)


def format_time(at: datetime) -> str:
    return at.astimezone().strftime("%H:%M")


def day_heading(at: datetime, *, now: datetime) -> str:
    """"Today", "Yesterday", or the date - the What Changed? groupings."""

    local_day = at.astimezone().date()
    today = now.astimezone().date()
    if local_day == today:
        return "Today"
    if (today - local_day).days == 1:
        return "Yesterday"
    return local_day.strftime("%A %d %B %Y")
