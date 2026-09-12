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
    assert sightings[0].source == "ipv6_nd"


def test_active_scan_tags_source_as_arp(monkeypatch):
    import scapy.all as scapy_module

    received = scapy_module.ARP(hwsrc="aa:bb:cc:dd:ee:ff", psrc="10.0.0.5")

    def fake_srp(pkt, **kwargs):
        return [(pkt, received)], []

    monkeypatch.setattr(scapy_module, "srp", fake_srp)
    sightings = scanner.active_scan(subnet="10.0.0.0/24", interface="eth0", timeout=1)
    assert len(sightings) == 1
    assert sightings[0].source == "arp"


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
    assert [s.source for s in sightings] == ["arp", "ipv6_nd"]


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
    assert sightings[0].source == "dhcp_client"


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


# --- DHCP server detection ---------------------------------------------


def _dhcp_reply_packet(
    *, src_mac="11:22:33:44:55:66", src_ip="192.168.1.1", chaddr_mac="aa:bb:cc:dd:ee:ff",
    yiaddr="0.0.0.0", giaddr="0.0.0.0", xid=0, options,
):
    """A BOOTREPLY (op=2), round-tripped through real serialization/parsing
    - unlike ``_dhcp_packet`` above, server-detection code depends on
    accurately reproducing what scapy *actually* hands back for a captured
    reply (e.g. message-type as a raw int, verified separately), not what a
    test happens to construct an in-memory object with.
    """

    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    chaddr = bytes.fromhex(chaddr_mac.replace(":", "")) + b"\x00" * 10
    pkt = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=yiaddr, chaddr=chaddr, giaddr=giaddr, xid=xid)
        / DHCP(options=options)
    )
    return Ether(bytes(pkt))


def _sniff_dhcp_server(monkeypatch, **passive_sniff_kwargs):
    import scapy.all as scapy_module

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    client_sightings = []
    server_sightings = []
    scanner.passive_sniff(
        on_sighting=client_sightings.append, on_dhcp_server=server_sightings.append,
        interface="eth0", **passive_sniff_kwargs,
    )
    return captured["prn"], client_sightings, server_sightings


def test_passive_sniff_dispatches_dhcp_offer_as_server_sighting(monkeypatch):
    handler, clients, servers = _sniff_dhcp_server(monkeypatch)

    handler(_dhcp_reply_packet(
        yiaddr="192.168.1.50", xid=12345,
        options=[("message-type", "offer"), ("server_id", "192.168.1.1"),
                 ("router", "192.168.1.1"), ("name_server", "192.168.1.1"), "end"],
    ))

    assert clients == []  # never merged into client inventory
    assert len(servers) == 1
    s = servers[0]
    assert s.interface == "eth0"
    assert s.server_id == "192.168.1.1"
    assert s.message_type == "offer"
    assert s.offered_ip == "192.168.1.50"
    assert s.transaction_id == 12345
    assert s.router == "192.168.1.1"
    assert s.dns == "192.168.1.1"
    assert s.relay_ip is None  # giaddr 0.0.0.0 -> no relay
    assert s.client_mac_evidence == "aa:bb:cc:dd:ee:ff"
    assert s.source_mac == "11:22:33:44:55:66"


def test_passive_sniff_dispatches_dhcp_ack_and_nak_as_server_sightings(monkeypatch):
    handler, _clients, servers = _sniff_dhcp_server(monkeypatch)

    handler(_dhcp_reply_packet(
        yiaddr="192.168.1.50",
        options=[("message-type", "ack"), ("server_id", "192.168.1.1"), "end"],
    ))
    handler(_dhcp_reply_packet(
        options=[("message-type", "nak"), ("server_id", "192.168.1.1"), "end"],
    ))

    assert [s.message_type for s in servers] == ["ack", "nak"]


def test_passive_sniff_relayed_reply_preserves_relay_and_server_identity_separately(monkeypatch):
    """The relay's own MAC/IP must never be attributed as the DHCP server's
    identity - the server identifier (option 54) is what identifies the
    server; the relay address/source are kept only as separate evidence."""

    handler, _clients, servers = _sniff_dhcp_server(monkeypatch)

    handler(_dhcp_reply_packet(
        src_mac="99:99:99:99:99:99", src_ip="10.0.0.254", giaddr="10.0.0.254",
        yiaddr="10.0.0.99", xid=999,
        options=[("message-type", "offer"), ("server_id", "10.0.0.9"), "end"],
    ))

    assert len(servers) == 1
    s = servers[0]
    assert s.server_id == "10.0.0.9"  # the actual server, from option 54
    assert s.source_mac == "99:99:99:99:99:99"  # the relay's MAC - evidence, not identity
    assert s.relay_ip == "10.0.0.254"


def test_passive_sniff_client_messages_never_treated_as_server_responses(monkeypatch):
    handler, clients, servers = _sniff_dhcp_server(monkeypatch)

    for message_type in ("discover", "request", "decline", "release", "inform"):
        pkt = _dhcp_packet(options=[
            ("message-type", message_type), ("requested_addr", "192.168.1.77"), "end",
        ])
        handler(pkt)

    assert servers == []
    # Each carries an explicit address hint, so all 5 are still ordinary
    # client sightings (existing client-path behavior, unaffected by this
    # feature) - what matters here is that none was misclassified as a
    # server response.
    assert len(clients) == 5


def test_passive_sniff_missing_server_id_produces_no_server_sighting(monkeypatch):
    handler, _clients, servers = _sniff_dhcp_server(monkeypatch)

    handler(_dhcp_reply_packet(options=[("message-type", "nak"), "end"]))

    assert servers == []


def test_passive_sniff_dhcp_server_detection_off_by_default_when_not_requested(monkeypatch):
    """Passing no ``on_dhcp_server`` at all means no server-side parsing
    happens - existing callers (that don't know about this feature) see no
    behavior change."""

    import scapy.all as scapy_module

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    clients = []
    scanner.passive_sniff(on_sighting=clients.append, interface="eth0")  # no on_dhcp_server
    handler = captured["prn"]

    handler(_dhcp_reply_packet(
        yiaddr="192.168.1.50",
        options=[("message-type", "offer"), ("server_id", "192.168.1.1"), "end"],
    ))

    assert clients == []  # no crash, and definitely not merged into client sightings


def test_passive_sniff_dhcp_disabled_also_disables_server_detection(monkeypatch):
    import scapy.all as scapy_module

    captured = {}

    def fake_sniff(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(scapy_module, "sniff", fake_sniff)
    servers = []
    scanner.passive_sniff(
        on_sighting=lambda s: None, on_dhcp_server=servers.append, interface="eth0", dhcp=False,
    )
    handler = captured["prn"]

    handler(_dhcp_reply_packet(
        options=[("message-type", "offer"), ("server_id", "192.168.1.1"), "end"]
    ))

    assert servers == []


# --- defensive option-value handling (white-box) ----------------------


def test_classify_dhcp_message_type_handles_real_numeric_codes():
    assert scanner._classify_dhcp_message_type(2) == "offer"
    assert scanner._classify_dhcp_message_type(5) == "ack"
    assert scanner._classify_dhcp_message_type(6) == "nak"


def test_classify_dhcp_message_type_rejects_client_codes():
    for code in (1, 3, 4, 7, 8):  # discover/request/decline/release/inform
        assert scanner._classify_dhcp_message_type(code) is None


def test_classify_dhcp_message_type_handles_strings_and_bytes():
    assert scanner._classify_dhcp_message_type("offer") == "offer"
    assert scanner._classify_dhcp_message_type("OFFER") == "offer"
    assert scanner._classify_dhcp_message_type(b"ack") == "ack"


def test_classify_dhcp_message_type_handles_malformed_input():
    assert scanner._classify_dhcp_message_type(None) is None
    assert scanner._classify_dhcp_message_type(9999) is None
    assert scanner._classify_dhcp_message_type("not-a-type") is None
    assert scanner._classify_dhcp_message_type(object()) is None
    assert scanner._classify_dhcp_message_type(True) is None  # bool is an int subclass - not a code


def test_dhcp_ip_option_handles_str_bytes_and_malformed():
    assert scanner._dhcp_ip_option("192.168.1.1") == "192.168.1.1"
    assert scanner._dhcp_ip_option(b"192.168.1.1") == "192.168.1.1"
    assert scanner._dhcp_ip_option("not-an-ip") is None
    assert scanner._dhcp_ip_option(None) is None
    assert scanner._dhcp_ip_option(b"\xff\xfe\x00") is None
    assert scanner._dhcp_ip_option(1234) is None
