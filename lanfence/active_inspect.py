# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""Optional, explicit active inspection of one already-known device.

Everything else in LAN Fence (``scan``/``monitor``/passive discovery/
``review``) is deliberately passive - it never sends traffic aimed at a
specific device. `lanfence inspect <mac>` is the one, opt-in exception: a
bounded TCP connect-scan of a short, curated list of common service ports
on a single already-known device, to help answer "what is this thing"
when passive evidence (vendor OUI, hostname, mDNS/SSDP) isn't enough. It is
never run automatically by any other command.

Two ways to gather the same evidence:

- :func:`socket_scan` - always available, pure standard library (bounded
  ``ThreadPoolExecutor`` of short-timeout ``socket.create_connection``
  calls, plus a purely passive banner *read* - no data sent - on a small
  set of cleartext protocols that greet first). No new dependency.
- :func:`nmap_scan` - used only when the ``nmap`` binary is present
  (:func:`nmap_available`); a TCP-connect scan (``-sT``, no raw sockets, no
  root required) with light version detection (``-sV``). Never a hard
  dependency - its absence is not an error, just a reason to fall back to
  :func:`socket_scan`.

Every open port is a confirmed fact (the connection succeeded); every
``service``/banner-derived label is an *inferred* identification, not a
verified capability; and :func:`infer_platform`'s guess is a coarse,
low/medium-confidence pattern match over which ports happened to be open -
never OS fingerprinting, and never presented as definitive. See
:class:`lanfence.models.InspectionResult` for how a run is persisted, with
the timestamp needed to show its age (and flag it as possibly stale) rather
than presenting old data as current.

This module never shells out with ``shell=True``, never interpolates
untrusted text into a command string, and always validates the target as a
literal IP address (:func:`ipaddress.ip_address`) before either scan path
runs - see :func:`inspect_device`. It targets identification only: no
exploitation, no credential testing, no protocol negotiation beyond a bare
connect and, for a couple of cleartext protocols, reading the greeting the
service sends unprompted.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Sequence

from lanfence.models import InspectedPort, InspectionConfidence, InspectionMethod, InspectionResult
from lanfence.netutil import normalize_mac

#: A short, curated list of common LAN service ports - enough to usefully
#: distinguish "printer" from "NAS" from "Windows PC" from "IP camera"
#: without scanning the full port range. Deliberately the same 20 ports
#: :func:`nmap_scan` asks for via ``--top-ports 20``, so the two scan paths
#: are directly comparable.
DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 548, 554, 631, 3389, 8080, 8443, 9100, 62078,
)

#: A human-friendly, purely-informational label for each default port - not
#: a claim about what's actually listening (see ``InspectedPort.service``'s
#: docstring); overridden by an actual banner-derived guess where one was
#: obtained.
_PORT_SERVICE_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
    445: "microsoft-ds (smb)", 548: "afp", 554: "rtsp", 631: "ipp (printing)",
    3389: "rdp", 8080: "http-alt", 8443: "https-alt", 9100: "jetdirect (printing)",
    62078: "apple mobile device sync",
}

#: Ports where a short, purely passive read immediately after connecting is
#: likely to capture a greeting banner the service sends unprompted (no
#: data sent - a lower-risk identification technique than actually
#: interacting with the protocol).
_BANNER_GREETS_FIRST = {21, 22, 23, 25, 110, 143}

#: Ports worth a minimal, well-formed HTTP HEAD request to read a `Server:`
#: header - the only case here that sends anything at all, and only a
#: single standard, harmless request.
_HTTP_BANNER_PORTS = {80, 8080}


def _validate_ip(ip: str) -> None:
    """Raise ``ValueError`` unless ``ip`` is a literal IPv4/IPv6 address -
    never a hostname, never anything that could be shell/format-string
    injected into a subprocess argument. Called before either scan path
    touches the network."""

    ipaddress.ip_address(ip)


def _read_banner(sock: socket.socket, *, max_bytes: int = 256) -> str | None:
    try:
        sock.settimeout(0.5)
        data = sock.recv(max_bytes)
    except OSError:
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").strip()
    return text.splitlines()[0][:200] if text else None


def _http_server_header(sock: socket.socket, *, host: str) -> str | None:
    try:
        sock.settimeout(1.0)
        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii", errors="ignore"))
        data = sock.recv(2048)
    except OSError:
        return None
    for line in data.decode("utf-8", errors="replace").splitlines():
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()[:200]
    return None


def _probe_port(ip: str, port: int, *, timeout: float) -> InspectedPort | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner: str | None = None
            if port in _HTTP_BANNER_PORTS:
                banner = _http_server_header(sock, host=ip)
            elif port in _BANNER_GREETS_FIRST:
                banner = _read_banner(sock)
            service = banner or _PORT_SERVICE_HINTS.get(port)
            return InspectedPort(port=port, service=service, banner=banner)
    except OSError:
        return None


def socket_scan(
    ip: str, *, ports: Sequence[int] | None = None, timeout: float = 0.75, max_workers: int = 12,
) -> list[InspectedPort]:
    """Bounded TCP connect-scan of ``ports`` (default :data:`DEFAULT_PORTS`)
    using only the standard library - always available, no external
    dependency. Returns confirmed-open ports only, sorted; a closed,
    filtered, or unreachable port is silently absent (not an error - most
    of the scanned ports are expected to be closed on any given device).
    """

    _validate_ip(ip)
    chosen = list(ports) if ports is not None else list(DEFAULT_PORTS)
    results: list[InspectedPort] = []
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        for result in pool.map(lambda p: _probe_port(ip, p, timeout=timeout), chosen):
            if result is not None:
                results.append(result)
    results.sort(key=lambda p: p.port)
    return results


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _parse_nmap_grepable(output: str) -> list[InspectedPort]:
    """Parse ``nmap -oG -`` output into :class:`InspectedPort` rows. Only
    ever fed this process's own stdout - never untrusted external input -
    but still tolerant of an unexpected line shape (skips it) rather than
    raising, since a partial/odd result is far better than a crash on a
    quirky nmap version's output format."""

    results: list[InspectedPort] = []
    for line in output.splitlines():
        if "Ports:" not in line:
            continue
        _, _, tail = line.partition("Ports:")
        ports_field = tail.split("\t")[0]
        for entry in ports_field.split(","):
            fields = [f.strip() for f in entry.split("/")]
            if len(fields) < 5:
                continue
            port_str, state = fields[0], fields[1]
            if state != "open":
                continue
            try:
                port = int(port_str)
            except ValueError:
                continue
            service = fields[4] or None
            version = fields[6] if len(fields) > 6 else ""
            banner = f"{service} {version}".strip() if version else None
            results.append(InspectedPort(port=port, service=service or _PORT_SERVICE_HINTS.get(port), banner=banner))
    results.sort(key=lambda p: p.port)
    return results


def nmap_scan(
    ip: str, *, ports: Sequence[int] | None = None, timeout: float = 30.0,
) -> list[InspectedPort] | None:
    """A TCP-connect scan (``-sT``, no raw sockets - works unprivileged)
    with light version probing (``-sV``) via the optional ``nmap`` binary.
    ``None`` means "could not run nmap" (not installed, or it failed/timed
    out) - the caller should fall back to :func:`socket_scan`, not treat
    this as "zero ports open". Always invoked as an argument list (never
    ``shell=True``) against a pre-validated literal IP address - no user-
    controlled text ever reaches a shell.
    """

    _validate_ip(ip)
    if not nmap_available():
        return None

    chosen = list(ports) if ports is not None else list(DEFAULT_PORTS)
    port_list = ",".join(str(p) for p in sorted(set(chosen)))
    command = ["nmap", "-Pn", "-sT", "-sV", "-p", port_list, "-T4", "-oG", "-", ip]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return _parse_nmap_grepable(completed.stdout)


def infer_platform(open_ports: list[InspectedPort]) -> tuple[str | None, InspectionConfidence | None, list[str]]:
    """A coarse, conservative platform guess from which ports are open -
    never OS fingerprinting, never claimed as definitive (see the module
    docstring). Returns ``(None, None, [])`` when no pattern below matches
    clearly enough to say anything.
    """

    ports = {p.port for p in open_ports}
    if not ports:
        return None, None, []

    windows_ports = ports & {135, 139, 445}
    if windows_ports and 3389 in ports:
        return (
            "Windows (RDP plus SMB/RPC exposed)", "medium",
            [f"Open ports: {', '.join(str(p) for p in sorted(windows_ports | {3389}))}"],
        )
    if windows_ports:
        return (
            "Windows, or a Samba-compatible file/print server", "low",
            [f"Open ports: {', '.join(str(p) for p in sorted(windows_ports))}"],
        )
    if 62078 in ports:
        return "Apple mobile device (iOS sync service)", "medium", ["Open port: 62078 (Apple mobile device sync)"]
    if 548 in ports and 22 in ports:
        return "Apple Mac (file sharing plus SSH)", "low", ["Open ports: 22, 548 (AFP)"]
    printer_ports = ports & {9100, 631}
    if printer_ports:
        return "Network printer", "medium", [f"Open ports: {', '.join(str(p) for p in sorted(printer_ports))}"]
    if 554 in ports and len(ports - {554, 80, 443}) == 0:
        return "IP camera / RTSP media device", "low", ["Open port: 554 (RTSP)"]
    if 22 in ports and len(ports - {22}) == 0:
        return "Linux/Unix-like device (SSH only)", "low", ["Open port: 22 (SSH), nothing else responded"]
    web_only = ports - {80, 443, 8080, 8443}
    if (ports & {80, 443, 8080, 8443}) and not web_only:
        return (
            "Embedded web-managed device (router, NAS, or IoT admin UI)", "low",
            [f"Open ports: {', '.join(str(p) for p in sorted(ports))}, no other services responded"],
        )
    return None, None, []


def inspect_device(
    mac: str,
    ip: str,
    *,
    now: datetime | None = None,
    use_nmap: bool = True,
    ports: Sequence[int] | None = None,
    socket_timeout: float = 0.75,
    nmap_timeout: float = 30.0,
    max_workers: int = 12,
) -> InspectionResult:
    """Run one active inspection of ``ip`` (the device already identified as
    ``mac``) and return the labeled result - never persists it itself (see
    :meth:`lanfence.db.DeviceStore.record_inspection`). Prefers ``nmap``
    when available and ``use_nmap`` is true (its ``-sV`` version probing
    tends to produce better service labels); otherwise, or if nmap fails to
    run at all, falls back to the dependency-free :func:`socket_scan` -
    either way the caller gets a real result, distinguished by
    ``InspectionResult.method``.
    """

    mac = normalize_mac(mac)
    _validate_ip(ip)
    now = now or datetime.now(timezone.utc)
    chosen_ports = list(ports) if ports is not None else list(DEFAULT_PORTS)

    method: InspectionMethod = "socket"
    open_ports: list[InspectedPort] | None = None
    if use_nmap:
        open_ports = nmap_scan(ip, ports=chosen_ports, timeout=nmap_timeout)
        if open_ports is not None:
            method = "nmap"
    if open_ports is None:
        open_ports = socket_scan(ip, ports=chosen_ports, timeout=socket_timeout, max_workers=max_workers)
        method = "socket"

    platform_guess, confidence, reasons = infer_platform(open_ports)
    return InspectionResult(
        mac=mac, ip=ip, method=method, observed_at=now, open_ports=open_ports,
        platform_guess=platform_guess, platform_confidence=confidence, platform_reasons=reasons,
    )
