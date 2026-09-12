# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

"""ARP/NDP-based device discovery: active sweeps and passive sniffing.

Observation-only: LAN Fence sends nothing to a target beyond a standard ARP
"who-has" request or IPv6 multicast ping (the same things any device on the
LAN does routinely to resolve an address) and never sends anything at all in
passive mode - it just listens. It never sends probe packets to individual
hosts, opens connections, or touches anything beyond reading ARP/ND traffic.

IPv6 has no equivalent of "sweep a /24" - a /64 can't be brute-forced - so
``active_scan_v6`` uses the standard alternative instead: a single ICMPv6 Echo
Request to the link-local all-nodes multicast address (``ff02::1``), which
every IPv6-enabled host on the link answers. Discovery is deliberately
link-local only: a link-local address is stable per-interface (unlike the
temporary/privacy addresses used at global scope, which rotate and would
otherwise look like a stream of "new devices"), and it needs no on-link
prefix knowledge the way an IPv4 subnet does.

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


#: Where an :class:`ArpSighting` came from - carried through explicitly
#: rather than inferred later, since the discovery pipeline used to discard
#: it. ``"dhcp_client"`` (a DHCPDISCOVER/REQUEST) is deliberately distinct
#: from ``"dhcp_ack"`` (the confirmed lease, from a *server* reply - see
#: :class:`DhcpServerSighting`) - a client asking for or being offered an
#: address is not proof it's using that address (see
#: :mod:`lanfence.engine`'s address-evidence handling), even though the
#: sighting is still perfectly good evidence the MAC is alive on the network.
SightingSource = str  # "arp" | "ipv6_nd" | "dhcp_client"


@dataclass(frozen=True)
class ArpSighting:
    """One MAC/IP pairing observed on the wire, from any discovery mechanism
    (ARP, IPv6 neighbor discovery, or DHCP)."""

    mac: str
    ip: str
    seen_at: datetime
    #: Self-reported hostname (DHCP option 12), when the sighting came from a
    #: DHCP packet. ``None`` for ARP/NDP sightings, which carry no hostname.
    hostname: str | None = None
    #: See :data:`SightingSource`. Defaults to ``"arp"`` for source
    #: compatibility with any caller constructing one without this field;
    #: every real construction site in this module sets it explicitly.
    source: SightingSource = "arp"


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


def local_mac(interface: str | None = None) -> str | None:
    """This host's own MAC address on ``interface`` (or the default one).

    Lets LAN Fence recognize its own network traffic - its own ARP requests
    during an active sweep, or its own frames a passive capture inevitably
    sees too - as itself rather than an unknown device (see
    :func:`lanfence.engine.apply_self_trust`).
    """

    try:
        scapy_module = _require_scapy()
        iface = interface or default_interface()
        if iface is None:
            return None
        mac = scapy_module.get_if_hwaddr(iface)
        return mac if mac and mac.lower() != "00:00:00:00:00:00" else None
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
        sightings.append(ArpSighting(mac=received.hwsrc, ip=received.psrc, seen_at=now, source="arp"))
    return sightings


#: Ethernet multicast MAC for the IPv6 all-nodes link-local multicast address
#: ff02::1 (RFC 2464: 33:33 followed by the low 32 bits of the IPv6 address).
_ALL_NODES_MULTICAST_MAC = "33:33:00:00:00:01"


def active_scan_v6(
    *,
    interface: str | None = None,
    timeout: float = 3.0,
) -> list[ArpSighting]:
    """Ping the IPv6 all-nodes multicast address and collect the replies.

    The IPv6 equivalent of an ARP sweep - a /64 can't be brute-forced the way
    :func:`active_scan` sweeps an IPv4 /24, so every IPv6-enabled host on the
    link is asked at once via a single Echo Request to ``ff02::1``. Each
    reply's own Ethernet source MAC and IPv6 source address are both on the
    captured frame, so - as with ARP - no separate address-resolution
    round-trip is needed. Raises :class:`ScannerUnavailable` under the same
    conditions as :func:`active_scan`.
    """

    scapy_module = _require_scapy()
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6

    kwargs = {"timeout": timeout, "verbose": False, "multi": True}
    if interface:
        kwargs["iface"] = interface

    request = (
        scapy_module.Ether(dst=_ALL_NODES_MULTICAST_MAC)
        / IPv6(dst="ff02::1")
        / ICMPv6EchoRequest()
    )
    try:
        answered, _unanswered = scapy_module.srp(request, **kwargs)
    except Exception as exc:  # noqa: BLE001 - see _looks_like_permission_error
        if _looks_like_permission_error(exc):
            raise ScannerUnavailable(
                "permission denied opening a raw socket - active scanning needs "
                "root (or CAP_NET_RAW). Re-run with sudo."
            ) from exc
        raise ScannerUnavailable(f"could not send IPv6 neighbor discovery pings: {exc}") from exc

    now = datetime.now(timezone.utc)
    sightings: list[ArpSighting] = []
    for _sent, received in answered:
        if not (received.haslayer(scapy_module.Ether) and received.haslayer(IPv6)):
            continue
        sightings.append(
            ArpSighting(
                mac=received[scapy_module.Ether].src,
                ip=received[IPv6].src,
                seen_at=now,
                source="ipv6_nd",
            )
        )
    return sightings


def has_ipv6(interface: str | None = None) -> bool:
    """True if ``interface`` (or the default one) has any IPv6 address.

    A link-local address is enough - that's all :func:`active_scan_v6` and
    the passive NDP path in :func:`passive_sniff` need.
    """

    try:
        scapy_module = _require_scapy()
        iface = interface or default_interface()
        if iface is None:
            return False
        return any(entry[2] == iface for entry in scapy_module.in6_getifaddr())
    except ScannerUnavailable:
        return False
    except Exception:  # noqa: BLE001 - best-effort guess
        return False


def _mac_from_chaddr(chaddr: bytes) -> str:
    return ":".join(f"{b:02x}" for b in chaddr[:6])


#: DHCP option 53 (message-type) codes that are ever legitimately sent by a
#: server (RFC 2131 s4.3) - everything else (discover/request/decline/
#: release/inform) is client-originated and never a server response, no
#: matter what BOOTP.op claims.
_DHCP_SERVER_MESSAGE_TYPES = {2: "offer", 5: "ack", 6: "nak"}
_DHCP_SERVER_MESSAGE_TYPE_NAMES = set(_DHCP_SERVER_MESSAGE_TYPES.values())


def _classify_dhcp_message_type(value: object) -> str | None:
    """Normalize DHCP option 53 to one of "offer"/"ack"/"nak", or ``None``
    if it's a client message type, missing, or unrecognized.

    Scapy dissects this as a raw ``int`` code in practice (verified against
    a real serialize/parse round-trip), not the human-readable name a test
    might construct a packet with - handle both defensively, along with
    bytes (seen elsewhere in this module for other options) and anything
    else malformed.
    """

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _DHCP_SERVER_MESSAGE_TYPES.get(value)
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii", errors="ignore").strip().lower()
        except Exception:  # noqa: BLE001
            return None
    if isinstance(value, str):
        value = value.strip().lower()
        return value if value in _DHCP_SERVER_MESSAGE_TYPE_NAMES else None
    return None


def _dhcp_ip_option(value: object) -> str | None:
    """Best-effort IPv4 string from a DHCP option that should be an IPField
    (server_id, router, name_server) - normally already ``str`` from scapy,
    but validated (and bytes decoded) defensively rather than trusted, since
    a malformed/adversarial packet is untrusted input, not a bug to crash on.
    """

    if isinstance(value, bytes):
        try:
            value = value.decode("ascii", errors="ignore")
        except Exception:  # noqa: BLE001
            return None
    if not isinstance(value, str) or not value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


@dataclass(frozen=True)
class DhcpServerSighting:
    """One DHCPOFFER/ACK/NAK reply, attributed to a network scope (the
    receiving interface - which already names a VLAN sub-interface like
    ``eth0.20`` at the OS level, so no separate VLAN field is claimed here;
    this module does not parse raw 802.1Q tags) and a claimed DHCP server
    identity (option 54) - never a device/client sighting. See
    ``lanfence/dhcp_server.py`` for why ``source_mac``/``relay_ip``/
    ``client_mac_evidence`` are evidence only, never treated as the
    server's identity.
    """

    interface: str | None
    server_id: str
    message_type: str  # "offer" | "ack" | "nak"
    observed_at: datetime
    source_ip: str | None = None
    source_mac: str | None = None
    relay_ip: str | None = None
    transaction_id: int | None = None
    #: BOOTP chaddr, echoed back in the reply - identifies the *client* this
    #: response was for, kept only as contextual evidence.
    client_mac_evidence: str | None = None
    offered_ip: str | None = None
    router: str | None = None
    dns: str | None = None


def passive_sniff(
    *,
    on_sighting: Callable[[ArpSighting], None],
    interface: str | None = None,
    stop_event: "SupportsIsSet | None" = None,
    packet_count: int = 0,
    dhcp: bool = True,
    on_dhcp_server: "Callable[[DhcpServerSighting], None] | None" = None,
) -> None:
    """Listen for ARP/ND/DHCP traffic and call ``on_sighting`` for each
    sighting seen.

    Blocks until ``stop_event`` is set (checked between packets) or
    ``packet_count`` packets have been processed (0 = unbounded - normal use is
    to run this in a background thread and set ``stop_event`` to end it).
    ``dhcp=False`` omits DHCP entirely, from both the capture filter and the
    packet handler - which also disables ``on_dhcp_server`` regardless of
    whether it's given, since there is no separate DHCP capture to gate
    only the server side of.

    ``on_dhcp_server``, when given, additionally reports DHCPOFFER/ACK/NAK
    replies (BOOTP op 2) as :class:`DhcpServerSighting` - a distinct
    observation type from ``on_sighting``'s client/ARP/NDP sightings, never
    merged with them. When omitted (the default), no extra parsing for
    server responses happens at all.
    """

    scapy_module = _require_scapy()
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, IPv6

    def _decode_dhcp_string(value: object) -> str | None:
        """Normalize a DHCP option value to ``str``.

        Despite carrying a plain string type (option 12), scapy hands this
        back as ``bytes`` rather than an already-decoded ``str`` on at least
        some scapy versions/platforms - decode defensively rather than
        assume either. The bytes are untrusted network input (a hostname a
        DHCP client can set to anything), so a malformed/non-UTF-8 value is
        replaced rather than raising.
        """

        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace") or None
        if isinstance(value, str):
            return value or None
        return None

    def _handle_dhcp_server(packet, bootp, options, message_type) -> None:
        server_id = _dhcp_ip_option(options.get("server_id"))
        if server_id is None:
            # A reply with no valid server identifier is a bounded
            # diagnostic, not a fabricated identity - drop it rather than
            # guess (e.g. from the relay/source address).
            log.warning(
                "dropping a DHCP %s reply with a missing/invalid server "
                "identifier (option 54) on %s", message_type, interface or "(default interface)",
            )
            return
        giaddr = getattr(bootp, "giaddr", None)
        relay_ip = giaddr if giaddr not in (None, "0.0.0.0") else None
        source_mac = packet[scapy_module.Ether].src if packet.haslayer(scapy_module.Ether) else None
        source_ip = packet[scapy_module.IP].src if packet.haslayer(scapy_module.IP) else None
        try:
            client_mac_evidence = _mac_from_chaddr(bytes(bootp.chaddr))
        except Exception:  # noqa: BLE001 - malformed chaddr must never crash monitoring
            client_mac_evidence = None
        offered_ip = bootp.yiaddr if bootp.yiaddr not in (None, "0.0.0.0") else None

        on_dhcp_server(
            DhcpServerSighting(
                interface=interface,
                server_id=server_id,
                message_type=message_type,
                observed_at=datetime.now(timezone.utc),
                source_ip=source_ip,
                source_mac=source_mac,
                relay_ip=relay_ip,
                transaction_id=int(bootp.xid) if bootp.xid is not None else None,
                client_mac_evidence=client_mac_evidence,
                offered_ip=offered_ip,
                router=_dhcp_ip_option(options.get("router")),
                dns=_dhcp_ip_option(options.get("name_server")),
            )
        )

    def _handle_dhcp(packet) -> None:
        if not packet.haslayer(BOOTP):
            return
        bootp = packet[BOOTP]
        # scapy's DHCP.options mixes (name, value) tuples with bare sentinel
        # strings like "end"/"pad" - filter to 2-tuples before unpacking, or
        # unpacking a 3+ char sentinel string raises ValueError.
        options = {opt[0]: opt[1] for opt in packet[DHCP].options if isinstance(opt, tuple) and len(opt) == 2}

        # op 2 (BOOTREPLY) is only ever sent by a server; op 1 (BOOTREQUEST)
        # is only ever sent by a client (RFC 2131 s2) - branch on that
        # first so a server's OFFER/ACK/NAK is never merged into client
        # inventory via chaddr (which identifies the *client*, not the
        # server), and a client's DISCOVER/REQUEST/DECLINE/RELEASE/INFORM
        # is never mistaken for a server response.
        if bootp.op == 2:
            if on_dhcp_server is not None:
                message_type = _classify_dhcp_message_type(options.get("message-type"))
                if message_type is not None:
                    _handle_dhcp_server(packet, bootp, options, message_type)
            return
        if bootp.op != 1:
            return

        ip = options.get("requested_addr")
        if not ip and bootp.yiaddr not in (None, "0.0.0.0"):
            ip = bootp.yiaddr
        if not ip and bootp.ciaddr not in (None, "0.0.0.0"):
            ip = bootp.ciaddr
        if not ip:
            # A bare initial DHCPDISCOVER carries no address hint yet - the
            # DHCPREQUEST/ACK that follows in the same handshake will.
            return
        on_sighting(
            ArpSighting(
                mac=_mac_from_chaddr(bytes(bootp.chaddr)),
                ip=ip,
                hostname=_decode_dhcp_string(options.get("hostname")),
                seen_at=datetime.now(timezone.utc),
                # A client asking for (or previously assigned) an address is
                # not proof it's using it (only a server's ACK confirms a
                # lease - see DhcpServerSighting/"dhcp_ack") - kept distinct
                # so address-evidence recording can tell the two apart,
                # while this is still perfectly good evidence the MAC and
                # any self-reported hostname are alive on the network.
                source="dhcp_client",
            )
        )

    def _handle(packet) -> None:
        now = datetime.now(timezone.utc)

        if packet.haslayer(scapy_module.ARP):
            arp = packet[scapy_module.ARP]
            # op 1 = who-has (request), op 2 = is-at (reply) - both carry a
            # live sender MAC/IP pairing worth recording.
            if arp.op in (1, 2):
                on_sighting(ArpSighting(mac=arp.hwsrc, ip=arp.psrc, seen_at=now, source="arp"))
            return

        if packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv6ND_NA):
            if not (packet.haslayer(scapy_module.Ether) and packet.haslayer(IPv6)):
                return
            src_ip = packet[IPv6].src
            # A Neighbor Solicitation sent for Duplicate Address Detection
            # (probing an address before claiming it) carries the unspecified
            # address, not a live one - nothing to record yet.
            if src_ip in ("::", ""):
                return
            on_sighting(
                ArpSighting(mac=packet[scapy_module.Ether].src, ip=src_ip, seen_at=now, source="ipv6_nd")
            )
            return

        if dhcp and packet.haslayer(DHCP):
            _handle_dhcp(packet)

    def _should_stop(_packet) -> bool:
        return bool(stop_event is not None and stop_event.is_set())

    dhcp_filter = " or (udp and (port 67 or port 68))" if dhcp else ""
    kwargs = {
        "filter": f"arp or icmp6{dhcp_filter}",
        "prn": _handle, "store": False, "stop_filter": _should_stop,
    }
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
