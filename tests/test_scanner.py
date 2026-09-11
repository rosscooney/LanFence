from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from lanfence import scanner


def _now():
    return datetime.now(timezone.utc)


def test_dedupe_latest_keeps_most_recent_and_normalizes_mac():
    t0 = _now()
    sightings = [
        scanner.ArpSighting(mac="AA:BB:CC:DD:EE:FF", ip="1.1.1.1", seen_at=t0),
        scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.2", seen_at=t0 + timedelta(seconds=5)),
    ]
    latest = scanner.dedupe_latest(sightings)
    assert list(latest.keys()) == ["aa:bb:cc:dd:ee:ff"]
    assert latest["aa:bb:cc:dd:ee:ff"].ip == "1.1.1.2"


def test_dedupe_latest_drops_unparseable_mac():
    sightings = [scanner.ArpSighting(mac="not-a-mac", ip="1.1.1.1", seen_at=_now())]
    assert scanner.dedupe_latest(sightings) == {}


@pytest.mark.parametrize(
    "exc,expected",
    [
        (PermissionError("nope"), True),
        (OSError(1, "Operation not permitted"), True),  # errno.EPERM
        (RuntimeError("Permission denied: could not open /dev/bpf0"), True),
        (ValueError("some other problem"), False),
    ],
)
def test_looks_like_permission_error(exc, expected):
    if isinstance(exc, OSError) and not isinstance(exc, PermissionError):
        exc.errno = 1  # errno.EPERM, to exercise the OSError branch directly
    assert scanner._looks_like_permission_error(exc) is expected


def test_active_scan_rejects_bad_subnet():
    with pytest.raises(ValueError):
        scanner.active_scan(subnet="not-a-subnet")


def test_local_subnet_returns_none_when_scanner_unavailable(monkeypatch):
    def _boom():
        raise scanner.ScannerUnavailable("no scapy")

    monkeypatch.setattr(scanner, "_require_scapy", _boom)
    assert scanner.local_subnet("eth0") is None
    assert scanner.default_interface() is None


def test_local_mac_returns_none_when_scanner_unavailable(monkeypatch):
    def _boom():
        raise scanner.ScannerUnavailable("no scapy")

    monkeypatch.setattr(scanner, "_require_scapy", _boom)
    assert scanner.local_mac("eth0") is None


def test_local_mac_returns_the_interfaces_hardware_address(monkeypatch):
    class _FakeScapy:
        @staticmethod
        def get_if_hwaddr(iface):
            assert iface == "eth0"
            return "AA:BB:CC:DD:EE:FF"

    monkeypatch.setattr(scanner, "_require_scapy", lambda: _FakeScapy())
    assert scanner.local_mac("eth0") == "AA:BB:CC:DD:EE:FF"


def test_local_mac_treats_all_zero_mac_as_unknown(monkeypatch):
    class _FakeScapy:
        @staticmethod
        def get_if_hwaddr(iface):
            return "00:00:00:00:00:00"

    monkeypatch.setattr(scanner, "_require_scapy", lambda: _FakeScapy())
    assert scanner.local_mac("eth0") is None


def test_local_mac_falls_back_to_default_interface(monkeypatch):
    class _FakeScapy:
        @staticmethod
        def get_if_hwaddr(iface):
            assert iface == "wlan0"
            return "11:22:33:44:55:66"

    monkeypatch.setattr(scanner, "_require_scapy", lambda: _FakeScapy())
    monkeypatch.setattr(scanner, "default_interface", lambda: "wlan0")
    assert scanner.local_mac(None) == "11:22:33:44:55:66"


def test_resolve_hostname_returns_none_on_failure():
    # 192.0.2.0/24 is TEST-NET-1 (RFC 5737) - guaranteed not to resolve.
    assert scanner.resolve_hostname("192.0.2.123", timeout=0.5) is None


# --- IPv6 neighbor discovery ------------------------------------------------


def test_has_ipv6_true_when_interface_has_any_v6_address(monkeypatch):
    import scapy.all as scapy_module

    monkeypatch.setattr(scapy_module, "in6_getifaddr", lambda: [("fe80::1", 32, "eth0")])
    assert scanner.has_ipv6("eth0") is True


def test_has_ipv6_false_when_interface_absent(monkeypatch):
    import scapy.all as scapy_module

    monkeypatch.setattr(scapy_module, "in6_getifaddr", lambda: [("fe80::1", 32, "wlan0")])
    assert scanner.has_ipv6("eth0") is False


def test_has_ipv6_false_when_scanner_unavailable(monkeypatch):
    def _boom():
        raise scanner.ScannerUnavailable("no scapy")

    monkeypatch.setattr(scanner, "_require_scapy", _boom)
    assert scanner.has_ipv6("eth0") is False


def test_active_scan_v6_permission_denied(monkeypatch):
    import scapy.all as scapy_module

    def fake_srp(*_args, **_kwargs):
        raise PermissionError("nope")

    monkeypatch.setattr(scapy_module, "srp", fake_srp)
    with pytest.raises(scanner.ScannerUnavailable, match="permission denied"):
        scanner.active_scan_v6(interface="eth0", timeout=1)


def test_active_scan_v6_generic_failure(monkeypatch):
    import scapy.all as scapy_module

    def fake_srp(*_args, **_kwargs):
        raise OSError("network down")

    monkeypatch.setattr(scapy_module, "srp", fake_srp)
    with pytest.raises(scanner.ScannerUnavailable, match="could not send IPv6"):
        scanner.active_scan_v6(interface="eth0", timeout=1)


def test_active_scan_v6_parses_replies(monkeypatch):
    import scapy.all as scapy_module
    from scapy.layers.inet6 import ICMPv6EchoReply, IPv6

    reply = scapy_module.Ether(src="aa:bb:cc:dd:ee:ff") / IPv6(src="fe80::1") / ICMPv6EchoReply()

    def fake_srp(pkt, **kwargs):
        assert kwargs.get("multi") is True
        return [(pkt, reply)], []

    monkeypatch.setattr(scapy_module, "srp", fake_srp)
    sightings = scanner.active_scan_v6(interface="eth0", timeout=1)
    assert len(sightings) == 1
    assert sightings[0].mac == "aa:bb:cc:dd:ee:ff"
    assert sightings[0].ip == "fe80::1"


def test_passive_sniff_uses_combined_arp_and_icmp6_filter(monkeypatch):
    import scapy.all as scapy_module

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    scanner.passive_sniff(on_sighting=lambda s: None, interface="eth0")
    assert captured["filter"] == "arp or icmp6 or (udp and (port 67 or port 68))"


def test_passive_sniff_filter_omits_dhcp_when_disabled(monkeypatch):
    import scapy.all as scapy_module

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    scanner.passive_sniff(on_sighting=lambda s: None, interface="eth0", dhcp=False)
    assert captured["filter"] == "arp or icmp6"


def test_passive_sniff_dispatches_arp_and_ndp_sightings(monkeypatch):
    import scapy.all as scapy_module
    from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, IPv6

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    sightings = []
    scanner.passive_sniff(on_sighting=sightings.append, interface="eth0")
    handler = captured["prn"]

    arp_reply = scapy_module.Ether(src="aa:bb:cc:dd:ee:ff") / scapy_module.ARP(
        op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="10.0.0.5"
    )
    handler(arp_reply)

    na_packet = scapy_module.Ether(src="11:22:33:44:55:66") / IPv6(src="fe80::1") / ICMPv6ND_NA()
    handler(na_packet)

    # A DAD probe (unspecified source) carries no live address yet - ignored.
    dad_probe = scapy_module.Ether(src="77:88:99:aa:bb:cc") / IPv6(src="::") / ICMPv6ND_NS()
    handler(dad_probe)

    assert [(s.mac, s.ip) for s in sightings] == [
        ("aa:bb:cc:dd:ee:ff", "10.0.0.5"),
        ("11:22:33:44:55:66", "fe80::1"),
    ]


def _dhcp_packet(*, chaddr_mac="aa:bb:cc:dd:ee:ff", options):
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    chaddr = bytes.fromhex(chaddr_mac.replace(":", "")) + b"\x00" * 10
    return (
        Ether(src=chaddr_mac)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=chaddr)
        / DHCP(options=options)
    )


def test_passive_sniff_dispatches_dhcp_hostname_sighting(monkeypatch):
    import scapy.all as scapy_module

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    sightings = []
    scanner.passive_sniff(on_sighting=sightings.append, interface="eth0")
    handler = captured["prn"]

    request = _dhcp_packet(options=[
        ("message-type", "request"), ("requested_addr", "192.168.1.77"),
        ("hostname", "Georges-iPhone"), "end",
    ])
    handler(request)

    assert len(sightings) == 1
    assert sightings[0].mac == "aa:bb:cc:dd:ee:ff"
    assert sightings[0].ip == "192.168.1.77"
    assert sightings[0].hostname == "Georges-iPhone"


def test_passive_sniff_decodes_bytes_hostname_option(monkeypatch):
    """Regression test: on at least some scapy versions/platforms, the
    "hostname" DHCP option (a plain string type) comes back as raw ``bytes``
    rather than an already-decoded ``str`` - passing that straight through
    used to crash downstream (`fingerprint.py`'s `kw.match in hostname.lower()`
    raised TypeError comparing str to the bytes' own .lower())."""

    import scapy.all as scapy_module

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    sightings = []
    scanner.passive_sniff(on_sighting=sightings.append, interface="eth0")
    handler = captured["prn"]

    request = _dhcp_packet(options=[
        ("message-type", "request"), ("requested_addr", "192.168.1.77"),
        ("hostname", b"Georges-iPhone"), "end",
    ])
    handler(request)

    assert len(sightings) == 1
    assert sightings[0].hostname == "Georges-iPhone"
    assert isinstance(sightings[0].hostname, str)


def test_passive_sniff_ignores_dhcp_discover_with_no_address_hint(monkeypatch):
    import scapy.all as scapy_module

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    sightings = []
    scanner.passive_sniff(on_sighting=sightings.append, interface="eth0")
    handler = captured["prn"]

    # A bare initial DHCPDISCOVER: no requested_addr option, yiaddr/ciaddr
    # both still 0.0.0.0 - nothing usable to record yet.
    bare_discover = _dhcp_packet(options=[("message-type", "discover"), "end"])
    handler(bare_discover)

    assert sightings == []


def test_passive_sniff_ignores_dhcp_when_disabled(monkeypatch):
    import scapy.all as scapy_module

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    sightings = []
    scanner.passive_sniff(on_sighting=sightings.append, interface="eth0", dhcp=False)
    handler = captured["prn"]

    request = _dhcp_packet(options=[
        ("message-type", "request"), ("requested_addr", "192.168.1.77"),
        ("hostname", "Georges-iPhone"), "end",
    ])
    handler(request)

    assert sightings == []
