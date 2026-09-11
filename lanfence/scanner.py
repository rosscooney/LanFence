# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""ARP-based device discovery: active sweeps and passive sniffing.

Observation-only: LAN Fence sends nothing to a target beyond a standard ARP
"who-has" request (the same thing any device on the LAN does routinely to
resolve an address) and never sends anything at all in passive mode - it just
listens. It never sends probe packets to individual hosts, opens connections,
or touches anything beyond reading ARP traffic.

Needs raw-socket access (``CAP_NET_RAW`` / root) and ``scapy``, both only
available on Linux in this project's supported deployment (Raspberry Pi /
Debian). Every entry point here raises :class:`ScannerUnavailable` with a
plain-language reason instead of crashing when either is missing, so the CLI
can degrade gracefully (e.g. skip passive monitoring, or tell the operator to
use ``sudo``).
"""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable

from lanfence.logging_config import get_logger

log = get_logger("scanner")


class ScannerUnavailable(RuntimeError):
    """Raised when active/passive scanning cannot run on this host right now."""


def _looks_like_permission_error(exc: BaseException) -> bool:
    """True if ``exc`` (from scapy opening a raw/BPF/pcap socket) is a
    permissions problem rather than something else going wrong.

    Scapy surfaces "you're not root" differently per platform/backend:
    ``PermissionError``/``OSError`` with ``errno.EPERM``/``EACCES`` on Linux,
    or its own ``Scapy_Exception`` with "Permission denied" in the message on
    the BPF (macOS/BSD) backend. Check both rather than one exception type.
    """

    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, OSError) and exc.errno in (errno.EPERM, errno.EACCES):
        return True
    return "permission denied" in str(exc).lower()


@dataclass(frozen=True)
class ArpSighting:
    """One MAC/IP pairing observed on the wire, from either scan mode."""

    mac: str
    ip: str
    seen_at: datetime


def _require_scapy():
    try:
        from scapy.all import conf  # noqa: F401
        import scapy.all as scapy_module
    except ImportError as exc:  # pragma: no cover - exercised via ScannerUnavailable path
        raise ScannerUnavailable(
            "scapy is not installed. Install the `scan` extra: "
            "pipx inject lanfence scapy (or pip install 'lanfence[scan]')"
        ) from exc
    return scapy_module


def default_interface() -> str | None:
    """Best-guess default network interface, or ``None`` if it can't be determined."""

    try:
        scapy_module = _require_scapy()
        route = scapy_module.conf.route.route("0.0.0.0")
        return route[0] if route and route[0] not in (None, "lo") else None
    except ScannerUnavailable:
        return None
    except Exception:  # noqa: BLE001 - best-effort guess
        return None


def local_subnet(interface: str | None = None) -> str | None:
    """CIDR subnet for ``interface`` (or the default one), e.g. "192.168.1.0/24"."""

    try:
        scapy_module = _require_scapy()
        iface = interface or default_interface()
        if iface is None:
            return None
        addr = scapy_module.get_if_addr(iface)
        if addr in (None, "0.0.0.0"):
            return None
        # Prefer the most specific (highest-prefixlen) directly-connected route
        # for this interface/address; skip the default route (mask 0) and
        # host routes (mask 32, e.g. VPN entries) which say nothing about the
        # LAN subnet.
        candidates = []
        for net, mask, gw, ifname, addr_, metric in scapy_module.conf.route.routes:
            if not (ifname == iface and addr_ == addr and 0 < mask < 0xFFFFFFFF):
                continue
            try:
                candidates.append(ipaddress.IPv4Network((net, mask), strict=False).prefixlen)
            except ValueError:
                continue  # non-contiguous mask (e.g. a multicast route entry)
        prefixlen = max(candidates) if candidates else 24
        network = ipaddress.ip_network(f"{addr}/{prefixlen}", strict=False)
        return str(network)
    except ScannerUnavailable:
        return None
    except Exception:  # noqa: BLE001 - best-effort guess
        return None


def active_scan(
    *,
    subnet: str,
    interface: str | None = None,
    timeout: float = 3.0,
) -> list[ArpSighting]:
    """Send ARP "who-has" requests across ``subnet`` and collect the replies.

    Raises :class:`ScannerUnavailable` if scapy is missing or the host lacks
    the raw-socket permission (CAP_NET_RAW) needed to send/receive ARP frames -
    typically meaning "re-run as root".
    """

    scapy_module = _require_scapy()
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"not a valid subnet: {subnet!r}") from exc

    kwargs = {"timeout": timeout, "verbose": False}
    if interface:
        kwargs["iface"] = interface

    request = scapy_module.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy_module.ARP(pdst=subnet)
    try:
        answered, _unanswered = scapy_module.srp(request, **kwargs)
    except Exception as exc:  # noqa: BLE001 - scapy's socket-open errors vary by
        # platform/backend (PermissionError, OSError, or its own Scapy_Exception
        # on the BPF/libpcap backends) - normalize all of them to one message.
        if _looks_like_permission_error(exc):
            raise ScannerUnavailable(
                "permission denied opening a raw socket - active scanning needs "
                "root (or CAP_NET_RAW). Re-run with sudo."
            ) from exc
        raise ScannerUnavailable(f"could not send ARP requests: {exc}") from exc

    now = datetime.now(timezone.utc)
    sightings: list[ArpSighting] = []
    for _sent, received in answered:
        sightings.append(ArpSighting(mac=received.hwsrc, ip=received.psrc, seen_at=now))
    return sightings


def passive_sniff(
    *,
    on_sighting: Callable[[ArpSighting], None],
    interface: str | None = None,
    stop_event: "SupportsIsSet | None" = None,
    packet_count: int = 0,
) -> None:
    """Listen for ARP traffic and call ``on_sighting`` for each packet seen.

    Blocks until ``stop_event`` is set (checked between packets) or
    ``packet_count`` packets have been processed (0 = unbounded - normal use is
    to run this in a background thread and set ``stop_event`` to end it).
    """

    scapy_module = _require_scapy()

    def _handle(packet) -> None:
        if not packet.haslayer(scapy_module.ARP):
            return
        arp = packet[scapy_module.ARP]
        # op 1 = who-has (request), op 2 = is-at (reply) - both carry a live
        # sender MAC/IP pairing worth recording.
        if arp.op not in (1, 2):
            return
        on_sighting(ArpSighting(mac=arp.hwsrc, ip=arp.psrc, seen_at=datetime.now(timezone.utc)))

    def _should_stop(_packet) -> bool:
        return bool(stop_event is not None and stop_event.is_set())

    kwargs = {"filter": "arp", "prn": _handle, "store": False, "stop_filter": _should_stop}
    if interface:
        kwargs["iface"] = interface
    if packet_count:
        kwargs["count"] = packet_count

    try:
        scapy_module.sniff(**kwargs)
    except Exception as exc:  # noqa: BLE001 - see _looks_like_permission_error
        if _looks_like_permission_error(exc):
            raise ScannerUnavailable(
                "permission denied opening a packet capture - passive monitoring "
                "needs root (or CAP_NET_RAW). Re-run with sudo."
            ) from exc
        raise ScannerUnavailable(f"could not start packet capture: {exc}") from exc


class SupportsIsSet:
    """Structural type for the ``threading.Event``-shaped object ``passive_sniff`` polls."""

    def is_set(self) -> bool:  # pragma: no cover - protocol stub
        raise NotImplementedError


def resolve_hostname(ip: str, *, timeout: float = 1.0) -> str | None:
    """Best-effort reverse-DNS lookup; ``None`` on any failure or timeout."""

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def dedupe_latest(sightings: Iterable[ArpSighting]) -> dict[str, ArpSighting]:
    """Collapse repeated sightings of the same MAC to the most recent one."""

    latest: dict[str, ArpSighting] = {}
    for sighting in sightings:
        with contextlib.suppress(Exception):
            from lanfence.netutil import normalize_mac

            mac = normalize_mac(sighting.mac)
            existing = latest.get(mac)
            if existing is None or sighting.seen_at >= existing.seen_at:
                latest[mac] = ArpSighting(mac=mac, ip=sighting.ip, seen_at=sighting.seen_at)
    return latest
