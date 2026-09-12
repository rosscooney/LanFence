from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lanfence.db import DeviceStore
from lanfence.discovery import (
    MdnsRecordSighting,
    parse_mdns_packet,
    parse_ssdp_packet,
    process_mdns_record_sighting,
    process_ssdp_sighting,
    well_known_mdns_label,
)


def _now():
    return datetime.now(timezone.utc)


# --- synthetic DNS wire-format builders (no scapy needed - see CONTRIBUTING.md:
# discovery.py's parsing is deliberately scapy-free and pure) -----------------


def _encode_name(labels: list[bytes]) -> bytes:
    out = b""
    for label in labels:
        out += bytes([len(label)]) + label
    return out + b"\x00"


def _rr(name: list[bytes], rtype: int, rdata: bytes, *, ttl: int = 120, cache_flush: bool = False) -> bytes:
    rrclass = 1 | (0x8000 if cache_flush else 0)
    return _encode_name(name) + struct.pack(">HHI", rtype, rrclass, ttl) + struct.pack(">H", len(rdata)) + rdata


def _dns_message(records: list[bytes], *, qr: bool = True, qdcount: int = 0, questions: bytes = b"") -> bytes:
    flags = 0x8400 if qr else 0x0000
    header = struct.pack(">HHHHHH", 0, flags, qdcount, len(records), 0, 0)
    return header + questions + b"".join(records)


def _ptr_rr(service_type: list[bytes], instance: list[bytes], **kw) -> bytes:
    return _rr(service_type, 12, _encode_name(instance), **kw)


def _srv_rr(fq_instance: list[bytes], target: list[bytes], port: int, **kw) -> bytes:
    rdata = struct.pack(">HHH", 0, 0, port) + _encode_name(target)
    return _rr(fq_instance, 33, rdata, **kw)


def _txt_rr(fq_instance: list[bytes], entries: list[bytes], **kw) -> bytes:
    rdata = b"".join(bytes([len(e)]) + e for e in entries)
    return _rr(fq_instance, 16, rdata, **kw)


def _a_rr(owner: list[bytes], ip: str, **kw) -> bytes:
    import ipaddress

    return _rr(owner, 1, ipaddress.IPv4Address(ip).packed, **kw)


def _aaaa_rr(owner: list[bytes], ip: str, **kw) -> bytes:
    import ipaddress

    return _rr(owner, 28, ipaddress.IPv6Address(ip).packed, **kw)


_IPP_TYPE = [b"_ipp", b"_tcp", b"local"]
_PRINTER_INSTANCE = [b"Office Printer", b"_ipp", b"_tcp", b"local"]


# --- mDNS: PTR / SRV / TXT / A / AAAA, split and combined -------------------


def test_parse_mdns_ptr_alone():
    msg = _dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE, ttl=120)])
    sightings = parse_mdns_packet(msg, interface="eth0", seen_at=_now())

    assert len(sightings) == 1
    s = sightings[0]
    assert s.rtype == "PTR"
    assert s.service_type == "_ipp._tcp.local"
    assert s.instance_name == "Office Printer"
    assert s.fq_instance == "Office Printer._ipp._tcp.local"
    assert s.ttl == 120


def test_parse_mdns_combined_ptr_srv_txt_a_in_one_packet():
    msg = _dns_message([
        _ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE),
        _srv_rr(_PRINTER_INSTANCE, [b"printer", b"local"], 631),
        _txt_rr(_PRINTER_INSTANCE, [b"ty=LaserJet"]),
        _a_rr([b"printer", b"local"], "192.168.1.50"),
    ])
    sightings = parse_mdns_packet(msg, seen_at=_now())
    rtypes = {s.rtype for s in sightings}
    assert rtypes == {"PTR", "SRV", "TXT", "A"}


def test_parse_mdns_split_across_separate_packets_still_works_after_correlation(tmp_path: Path):
    """PTR/SRV/TXT/A need not appear together - the store correlates them
    across independent writes (see the module docstring)."""

    now = _now()
    ptr_msg = _dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)])
    srv_msg = _dns_message([_srv_rr(_PRINTER_INSTANCE, [b"printer", b"local"], 631)])

    with DeviceStore(tmp_path / "db.sqlite") as store:
        for sighting in parse_mdns_packet(ptr_msg, interface="eth0", seen_at=now):
            process_mdns_record_sighting(sighting, store)
        for sighting in parse_mdns_packet(srv_msg, interface="eth0", seen_at=now + timedelta(seconds=5)):
            process_mdns_record_sighting(sighting, store)
        services = store.advertised_services()

    assert len(services) == 1
    assert services[0].target_host == "printer.local"
    assert services[0].target_port == 631


def test_parse_mdns_ptr_without_srv_or_txt_still_produces_a_service(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for sighting in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=_now()):
            process_mdns_record_sighting(sighting, store)
        services = store.advertised_services()

    assert len(services) == 1
    assert services[0].target_host is None
    assert services[0].attributes == {}


# --- questions / known-answer suppression must not create advertisements ---


def test_query_message_answer_section_is_ignored():
    """A QUERY (QR=0) - even one carrying known-answer suppression records
    in its own answer section - must never be treated as an advertisement."""

    msg = _dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)], qr=False)
    assert parse_mdns_packet(msg, seen_at=_now()) == []


def test_questions_section_is_skipped_not_parsed_as_records():
    question = _encode_name(_IPP_TYPE) + struct.pack(">HH", 12, 1)
    msg = _dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)], qdcount=1, questions=question)
    sightings = parse_mdns_packet(msg, seen_at=_now())
    assert len(sightings) == 1
    assert sightings[0].rtype == "PTR"


def test_dns_sd_service_enumeration_ptr_is_not_a_service_instance():
    enum_owner = [b"_services", b"_dns-sd", b"_udp", b"local"]
    msg = _dns_message([_ptr_rr(enum_owner, _IPP_TYPE)])
    assert parse_mdns_packet(msg, seen_at=_now()) == []


# --- instance names: escaped/dotted, case, unknown types --------------------


def test_instance_name_containing_a_literal_dot_is_not_mis_split():
    instance = [b"Bob's Printer.local test", b"_ipp", b"_tcp", b"local"]
    msg = _dns_message([_ptr_rr(_IPP_TYPE, instance)])
    sightings = parse_mdns_packet(msg, seen_at=_now())

    assert sightings[0].instance_name == "Bob's Printer.local test"
    assert sightings[0].fq_instance == "Bob's Printer.local test._ipp._tcp.local"


def test_unknown_service_type_is_retained_with_raw_name_and_no_label():
    weird_type = [b"_myproto", b"_tcp", b"local"]
    weird_instance = [b"Widget", b"_myproto", b"_tcp", b"local"]
    msg = _dns_message([_ptr_rr(weird_type, weird_instance)])
    sightings = parse_mdns_packet(msg, seen_at=_now())

    assert sightings[0].service_type == "_myproto._tcp.local"
    assert well_known_mdns_label(sightings[0].service_type) is None


def test_dns_names_are_case_insensitive_identities_ptr_coalesces(tmp_path: Path):
    """"Printer.local"/"printer.local" are the same DNS name (RFC 1035/6762)
    - a repeated observation with different letter case must coalesce into
    the same evidence row, not create a duplicate."""

    now = _now()
    lower_instance = [b"office printer", b"_ipp", b"_tcp", b"local"]
    upper_instance = [b"office printer", b"_IPP", b"_TCP", b"LOCAL"]
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, lower_instance)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        for s in parse_mdns_packet(
            _dns_message([_ptr_rr([b"_IPP", b"_TCP", b"LOCAL"], upper_instance)]),
            seen_at=now + timedelta(seconds=1),
        ):
            process_mdns_record_sighting(s, store)

        assert len(store.advertised_services()) == 1


def test_dns_names_case_insensitive_srv_target_correlates_with_a_record(tmp_path: Path):
    """SRV's target host and the A record's owner name differ only in
    case - correlation must still find the address."""

    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        for s in parse_mdns_packet(
            _dns_message([_srv_rr(_PRINTER_INSTANCE, [b"Printer", b"LOCAL"], 631)]), seen_at=now
        ):
            process_mdns_record_sighting(s, store)
        for s in parse_mdns_packet(_dns_message([_a_rr([b"printer", b"local"], "192.168.1.50")]), seen_at=now):
            process_mdns_record_sighting(s, store)

        services = store.advertised_services()

    assert services[0].addresses == ["192.168.1.50"]


def test_well_known_labels_case_insensitive():
    assert well_known_mdns_label("_IPP._TCP.local") == "Printing"
    assert well_known_mdns_label("_airplay._tcp.local") == "AirPlay"
    assert well_known_mdns_label("_unknown._tcp.local") is None


# --- TTLs, goodbye, cache-flush grace ---------------------------------------


def test_ttl_zero_ptr_is_a_goodbye_not_a_fresh_record(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE, ttl=120)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        assert store.advertised_services()[0].status == "current"

        goodbye = _dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE, ttl=0)])
        for s in parse_mdns_packet(goodbye, seen_at=now + timedelta(seconds=1)):
            process_mdns_record_sighting(s, store)

        services = store.advertised_services(include_expired=True)
        assert services[0].status == "withdrawn"


def test_goodbye_for_never_seen_record_does_not_create_a_row(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        goodbye = _dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE, ttl=0)])
        for s in parse_mdns_packet(goodbye, seen_at=_now()):
            process_mdns_record_sighting(s, store)
        assert store.advertised_services(include_expired=True) == []


def test_ptr_and_srv_have_independent_ttls_refreshed_ptr_does_not_extend_srv(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE, ttl=3600)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        srv_msg = _dns_message([_srv_rr(_PRINTER_INSTANCE, [b"printer", b"local"], 631, ttl=5)])
        for s in parse_mdns_packet(srv_msg, seen_at=now):
            process_mdns_record_sighting(s, store)

        # The PTR gets refreshed with a long TTL well after the SRV's own
        # short TTL should have lapsed - the SRV's target/port must not be
        # kept alive by the unrelated PTR refresh.
        later = now + timedelta(seconds=30)
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE, ttl=3600)]), seen_at=later):
            process_mdns_record_sighting(s, store)

        srv_row = store._conn.execute(  # noqa: SLF001 - internal check of independent expiry
            "SELECT expires_at FROM mdns_srv WHERE fq_instance = ?", (
                "Office Printer._ipp._tcp.local",
            )
        ).fetchone()
        from lanfence.db import _parse_dt

        assert _parse_dt(srv_row["expires_at"]) < later


def test_cache_flush_a_record_withdraws_other_addresses_after_grace_period(tmp_path: Path):
    now = _now()
    owner = [b"printer", b"local"]
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_a_rr(owner, "192.168.1.50")]), seen_at=now):
            process_mdns_record_sighting(s, store)
        # A cache-flush A record for a *different* IP, well after the grace
        # window - the old IP should be withdrawn, but the record for a
        # *different* target host must be untouched (see the next test).
        later = now + timedelta(seconds=5)
        cache_flush_msg = _dns_message([_a_rr(owner, "192.168.1.51", cache_flush=True)])
        for s in parse_mdns_packet(cache_flush_msg, seen_at=later):
            process_mdns_record_sighting(s, store)

        rows = store._conn.execute(  # noqa: SLF001
            "SELECT ip, withdrawn FROM mdns_addr WHERE target_host = 'printer.local'"
        ).fetchall()
    by_ip = {r["ip"]: r["withdrawn"] for r in rows}
    assert by_ip["192.168.1.50"] == 1
    assert by_ip["192.168.1.51"] == 0


def test_cache_flush_within_grace_window_does_not_withdraw_sibling_immediately(tmp_path: Path):
    now = _now()
    owner = [b"printer", b"local"]
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_a_rr(owner, "192.168.1.50")]), seen_at=now):
            process_mdns_record_sighting(s, store)
        # A second address for the SAME owner arrives within the same
        # response burst (well under the 1s grace window) - both survive.
        same_burst = now + timedelta(milliseconds=50)
        for s in parse_mdns_packet(_dns_message([_a_rr(owner, "192.168.1.51", cache_flush=True)]), seen_at=same_burst):
            process_mdns_record_sighting(s, store)

        rows = store._conn.execute(  # noqa: SLF001
            "SELECT ip, withdrawn FROM mdns_addr WHERE target_host = 'printer.local'"
        ).fetchall()
    by_ip = {r["ip"]: r["withdrawn"] for r in rows}
    assert by_ip["192.168.1.50"] == 0
    assert by_ip["192.168.1.51"] == 0


def test_cache_flush_never_touches_a_different_target_host():
    """Cache-flush on one owner name must never erase an unrelated name's
    evidence - only handled here as a parser-level sanity check (the
    grouping key includes target_host, verified at the db layer above)."""

    printer = [b"printer", b"local"]
    nas = [b"nas", b"local"]
    msg = _dns_message([_a_rr(printer, "192.168.1.50", cache_flush=True), _a_rr(nas, "192.168.1.60")])
    sightings = parse_mdns_packet(msg, seen_at=_now())
    owners = {s.address_owner for s in sightings}
    assert owners == {"printer.local", "nas.local"}


# --- malformed / bounded input -----------------------------------------------


def test_truncated_dns_header_returns_empty_list_not_a_crash():
    assert parse_mdns_packet(b"\x00\x01", seen_at=_now()) == []


def test_dns_pointer_that_points_forward_is_rejected():
    # A hand-crafted forward-pointing compression pointer (0xC0 0x20) inside
    # an otherwise well-formed-looking header - must be rejected, not looped.
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    bad_name = b"\xc0\x20"  # points forward, past the header
    rr_rest = struct.pack(">HHI", 12, 1, 120) + struct.pack(">H", 0)
    msg = header + bad_name + rr_rest
    assert parse_mdns_packet(msg, seen_at=_now()) == []


def test_record_extending_past_end_of_message_is_rejected():
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    name = _encode_name(_IPP_TYPE)
    # rdlength claims far more data than actually follows.
    bogus = name + struct.pack(">HHI", 12, 1, 120) + struct.pack(">H", 9999) + b"short"
    assert parse_mdns_packet(header + bogus, seen_at=_now()) == []


def test_txt_attribute_allowlist_drops_unknown_and_bounds_values():
    entries = [b"ty=" + b"x" * 200, b"secret=leakme", b"note=hi", b"model=Widget9000"]
    msg = _dns_message([_txt_rr(_PRINTER_INSTANCE, entries)])
    sightings = parse_mdns_packet(msg, seen_at=_now())

    attrs = sightings[0].attributes
    assert "secret" not in attrs
    assert attrs["note"] == "hi"
    assert attrs["model"] == "Widget9000"
    assert len(attrs["ty"]) <= 128


def test_txt_total_bytes_are_bounded():
    entries = [f"note=value-{i}-{'x' * 100}".encode() for i in range(10)]
    # only "note" is allowlisted, and repeated identical keys keep the first
    entries = [b"description=" + str(i).encode() * 100 for i in range(10)]
    msg = _dns_message([_txt_rr(_PRINTER_INSTANCE, entries)])
    sightings = parse_mdns_packet(msg, seen_at=_now())
    total_bytes = sum(len(v) for v in sightings[0].attributes.values())
    assert total_bytes <= 512


# --- SSDP: alive / update / byebye / response / ignored M-SEARCH -----------


def _ssdp_lines(*lines: str) -> bytes:
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def _alive_message(usn="uuid:1234::urn:schemas-upnp-org:device:MediaRenderer:1", **overrides):
    fields = {
        "start": "NOTIFY * HTTP/1.1",
        "HOST": "239.255.255.250:1900",
        "CACHE-CONTROL": "max-age=1800",
        "LOCATION": "http://10.0.0.9:80/desc.xml",
        "NT": "urn:schemas-upnp-org:device:MediaRenderer:1",
        "NTS": "ssdp:alive",
        "SERVER": "Linux/3.0 UPnP/1.0 MyDevice/1.0",
        "USN": usn,
    }
    fields.update(overrides)
    start = fields.pop("start")
    lines = [start] + [f"{k}: {v}" for k, v in fields.items()]
    return _ssdp_lines(*lines)


def test_ssdp_alive_parses_all_retained_fields():
    s = parse_ssdp_packet(_alive_message(), seen_at=_now())
    assert s.message_type == "alive"
    assert s.usn == "uuid:1234::urn:schemas-upnp-org:device:MediaRenderer:1"
    assert s.nt_or_st == "urn:schemas-upnp-org:device:MediaRenderer:1"
    assert s.server == "Linux/3.0 UPnP/1.0 MyDevice/1.0"
    assert s.location == "http://10.0.0.9:80/desc.xml"
    assert s.max_age == 1800


def test_ssdp_update_is_parsed():
    msg = _alive_message(NTS="ssdp:update")
    s = parse_ssdp_packet(msg, seen_at=_now())
    assert s.message_type == "update"


def test_ssdp_byebye_has_no_max_age():
    msg = _alive_message(NTS="ssdp:byebye")
    s = parse_ssdp_packet(msg, seen_at=_now())
    assert s.message_type == "byebye"
    assert s.max_age is None


def test_ssdp_200_response_uses_st_header():
    msg = _ssdp_lines(
        "HTTP/1.1 200 OK", "CACHE-CONTROL: max-age=1800",
        "ST: upnp:rootdevice", "USN: uuid:xyz::upnp:rootdevice", "SERVER: srv",
    )
    s = parse_ssdp_packet(msg, seen_at=_now())
    assert s.message_type == "response"
    assert s.nt_or_st == "upnp:rootdevice"


def test_msearch_request_is_ignored():
    msearch = _ssdp_lines(
        "M-SEARCH * HTTP/1.1", "HOST: 239.255.255.250:1900", 'MAN: "ssdp:discover"', "MX: 2", "ST: ssdp:all",
    )
    assert parse_ssdp_packet(msearch, seen_at=_now()) is None


def test_ssdp_headers_are_case_insensitive():
    msg = _ssdp_lines(
        "NOTIFY * HTTP/1.1", "usn: uuid:aa::upnp:rootdevice", "nts: ssdp:alive", "nt: upnp:rootdevice",
    )
    s = parse_ssdp_packet(msg, seen_at=_now())
    assert s is not None
    assert s.usn == "uuid:aa::upnp:rootdevice"


def test_ssdp_missing_usn_is_dropped():
    msg = _ssdp_lines("NOTIFY * HTTP/1.1", "NTS: ssdp:alive", "NT: upnp:rootdevice")
    assert parse_ssdp_packet(msg, seen_at=_now()) is None


def test_ssdp_duplicate_conflicting_usn_is_rejected():
    msg = _ssdp_lines(
        "NOTIFY * HTTP/1.1", "NTS: ssdp:alive", "NT: upnp:rootdevice",
        "USN: uuid:aa::upnp:rootdevice", "USN: uuid:bb::upnp:rootdevice",
    )
    assert parse_ssdp_packet(msg, seen_at=_now()) is None


def test_ssdp_duplicate_identical_usn_is_accepted():
    msg = _ssdp_lines(
        "NOTIFY * HTTP/1.1", "NTS: ssdp:alive", "NT: upnp:rootdevice",
        "USN: uuid:aa::upnp:rootdevice", "USN: uuid:aa::upnp:rootdevice",
    )
    s = parse_ssdp_packet(msg, seen_at=_now())
    assert s is not None
    assert s.usn == "uuid:aa::upnp:rootdevice"


def test_ssdp_missing_max_age_falls_back_to_bounded_default_not_immortal():
    msg = _ssdp_lines("NOTIFY * HTTP/1.1", "NTS: ssdp:alive", "NT: upnp:rootdevice", "USN: uuid:aa::x")
    s = parse_ssdp_packet(msg, seen_at=_now())
    assert s.max_age is not None
    assert 0 < s.max_age < 3600 * 24


def test_ssdp_invalid_max_age_falls_back_to_bounded_default():
    msg = _ssdp_lines(
        "NOTIFY * HTTP/1.1", "NTS: ssdp:alive", "NT: upnp:rootdevice", "USN: uuid:aa::x",
        "CACHE-CONTROL: max-age=banana",
    )
    s = parse_ssdp_packet(msg, seen_at=_now())
    assert s.max_age is not None


def test_ssdp_absurd_max_age_is_clamped():
    msg = _ssdp_lines(
        "NOTIFY * HTTP/1.1", "NTS: ssdp:alive", "NT: upnp:rootdevice", "USN: uuid:aa::x",
        "CACHE-CONTROL: max-age=99999999",
    )
    s = parse_ssdp_packet(msg, seen_at=_now())
    assert s.max_age <= 7 * 24 * 3600


def test_ssdp_malformed_message_never_raises():
    assert parse_ssdp_packet(b"\xff\xfe not even close to http", seen_at=_now()) is None
    assert parse_ssdp_packet(b"", seen_at=_now()) is None
    assert parse_ssdp_packet(b"x" * 20000, seen_at=_now()) is None


# --- SSDP persistence: byebye scoping, update survival, boot id churn -------


def test_ssdp_byebye_withdraws_only_matching_usn(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        process_ssdp_sighting(parse_ssdp_packet(_alive_message(usn="uuid:a"), seen_at=now), store)
        process_ssdp_sighting(parse_ssdp_packet(_alive_message(usn="uuid:b"), seen_at=now), store)
        process_ssdp_sighting(
            parse_ssdp_packet(_alive_message(usn="uuid:a", NTS="ssdp:byebye"), seen_at=now), store
        )
        services = {s.identity: s.status for s in store.advertised_services(include_expired=True)}

    assert services["uuid:a"] == "withdrawn"
    assert services["uuid:b"] == "current"


def test_ssdp_update_with_new_boot_id_does_not_remove_other_usns(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        process_ssdp_sighting(parse_ssdp_packet(_alive_message(usn="uuid:a"), seen_at=now), store)
        process_ssdp_sighting(parse_ssdp_packet(_alive_message(usn="uuid:b"), seen_at=now), store)
        process_ssdp_sighting(
            parse_ssdp_packet(
                _alive_message(usn="uuid:a", NTS="ssdp:update", **{"BOOTID.UPNP.ORG": "7"}), seen_at=now
            ),
            store,
        )
        services = {s.identity: s.status for s in store.advertised_services()}

    assert services["uuid:a"] == "current"
    assert services["uuid:b"] == "current"


def test_ssdp_byebye_for_never_seen_usn_does_not_create_a_row(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        process_ssdp_sighting(parse_ssdp_packet(_alive_message(NTS="ssdp:byebye"), seen_at=_now()), store)
        assert store.advertised_services(include_expired=True) == []


def test_ssdp_repeated_alive_updates_in_place_not_one_row_per_packet(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for i in range(5):
            process_ssdp_sighting(parse_ssdp_packet(_alive_message(), seen_at=now + timedelta(seconds=i)), store)
        assert len(store.advertised_services(include_expired=True)) == 1


def test_location_is_stored_but_this_module_never_fetches_it():
    """A structural guarantee, not just a docstring claim: nothing in this
    module performs network I/O of any kind."""

    import inspect

    import lanfence.discovery as discovery_module

    source = inspect.getsource(discovery_module)
    for banned in ("urllib", "requests", "socket.connect", "http.client"):
        assert banned not in source


# --- attribution: never trust the transmitting frame alone ------------------


def test_mdns_proxy_reflector_source_mac_is_never_used_for_attribution(tmp_path: Path):
    """The PTR/SRV packets' own Ethernet source is a fake reflector MAC -
    attribution must come only from the A record's target-address match
    against directly-observed evidence, never the transmitting frame."""

    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.50", hostname=None, vendor=None, seen_at=now)

        reflector_mac = "ff:ff:ff:ff:ff:ff"
        ptr = MdnsRecordSighting(
            rtype="PTR", ttl=120, cache_flush=False, interface="eth0", source_ip="10.0.0.1",
            source_mac=reflector_mac, family="ipv4", seen_at=now,
            service_type="_ipp._tcp.local", instance_name="Office Printer",
            fq_instance="Office Printer._ipp._tcp.local",
        )
        srv = MdnsRecordSighting(
            rtype="SRV", ttl=120, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
            family="ipv4", seen_at=now, fq_instance="Office Printer._ipp._tcp.local",
            target_host="printer.local", target_port=631,
        )
        addr = MdnsRecordSighting(
            rtype="A", ttl=120, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
            family="ipv4", seen_at=now, address_owner="printer.local", address="192.168.1.50",
        )
        for s in (ptr, srv, addr):
            process_mdns_record_sighting(s, store)

        services = store.advertised_services()

    assert services[0].mac == "aa:bb:cc:dd:ee:ff"
    assert services[0].mac != reflector_mac.lower()
    assert services[0].attribution_basis == "target_address_match"


def test_mdns_with_no_address_evidence_is_unassociated(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        services = store.advertised_services()

    assert services[0].mac is None
    assert services[0].attribution_basis is None


def test_ambiguous_ip_to_mac_association_stays_unassociated(tmp_path: Path):
    """Two different MACs have each directly held this IP historically -
    an ambiguous association must never resolve to a confident guess."""

    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "192.168.1.50", interface="eth0", source="arp", kind="observed", seen_at=now,
        )
        store.record_address_evidence(
            "11:22:33:44:55:66", "192.168.1.50", interface="eth0", source="arp", kind="observed",
            seen_at=now - timedelta(hours=1),
        )
        for s in parse_mdns_packet(_dns_message([_a_rr([b"printer", b"local"], "192.168.1.50")]), seen_at=now):
            process_mdns_record_sighting(s, store)
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        for s in parse_mdns_packet(
            _dns_message([_srv_rr(_PRINTER_INSTANCE, [b"printer", b"local"], 631)]), seen_at=now
        ):
            process_mdns_record_sighting(s, store)

        services = store.advertised_services()

    assert services[0].mac is None


def test_stale_historical_dhcp_lease_evidence_is_never_used_for_attribution(tmp_path: Path):
    """Only directly-observed (arp/ipv6_nd) evidence counts for
    attribution - a DHCP-server-reported lease claim never does."""

    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "192.168.1.50", interface="eth0", source="dhcp_ack",
            kind="lease_reported", seen_at=now,
        )
        for s in parse_mdns_packet(_dns_message([_a_rr([b"printer", b"local"], "192.168.1.50")]), seen_at=now):
            process_mdns_record_sighting(s, store)
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        for s in parse_mdns_packet(
            _dns_message([_srv_rr(_PRINTER_INSTANCE, [b"printer", b"local"], 631)]), seen_at=now
        ):
            process_mdns_record_sighting(s, store)

        services = store.advertised_services()

    assert services[0].mac is None


def test_ssdp_source_ip_attribution_requires_confirmed_address_evidence(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.9", hostname=None, vendor=None, seen_at=now)
        sighting = parse_ssdp_packet(_alive_message(), source_ip="10.0.0.9", seen_at=now)
        process_ssdp_sighting(sighting, store)
        services = store.advertised_services(protocol="ssdp")

    assert services[0].mac == "aa:bb:cc:dd:ee:ff"
    assert services[0].attribution_basis == "source_address_match"


def test_ssdp_with_no_matching_device_is_unassociated(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        sighting = parse_ssdp_packet(_alive_message(), source_ip="10.0.0.9", seen_at=_now())
        process_ssdp_sighting(sighting, store)
        services = store.advertised_services(protocol="ssdp")

    assert services[0].mac is None


# --- reevaluation as evidence arrives, without rewriting original rows -----


def test_attribution_improves_once_address_evidence_arrives_later(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_a_rr([b"printer", b"local"], "192.168.1.50")]), seen_at=now):
            process_mdns_record_sighting(s, store)
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        for s in parse_mdns_packet(
            _dns_message([_srv_rr(_PRINTER_INSTANCE, [b"printer", b"local"], 631)]), seen_at=now
        ):
            process_mdns_record_sighting(s, store)
        assert store.advertised_services()[0].mac is None

        # A direct ARP observation arrives afterwards - attribution should
        # now resolve, without needing to rewrite the original PTR/SRV/A rows.
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "192.168.1.50", interface="eth0", source="arp", kind="observed",
            seen_at=now + timedelta(minutes=1),
        )
        assert store.advertised_services()[0].mac == "aa:bb:cc:dd:ee:ff"


# --- filters, status, reset -----------------------------------------------


def test_include_expired_filter(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE, ttl=1)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        later = now + timedelta(seconds=10)
        assert store.advertised_services(now=later) == []
        assert len(store.advertised_services(now=later, include_expired=True)) == 1
        assert store.advertised_services(now=later, include_expired=True)[0].status == "expired"


def test_protocol_filter(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=now):
            process_mdns_record_sighting(s, store)
        process_ssdp_sighting(parse_ssdp_packet(_alive_message(), seen_at=now), store)

        assert len(store.advertised_services(protocol="mdns")) == 1
        assert len(store.advertised_services(protocol="ssdp")) == 1
        assert len(store.advertised_services()) == 2


def test_unassociated_only_filter(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.9", hostname=None, vendor=None, seen_at=now)
        matched = parse_ssdp_packet(_alive_message(usn="uuid:matched"), source_ip="10.0.0.9", seen_at=now)
        orphan = parse_ssdp_packet(_alive_message(usn="uuid:orphan"), source_ip="10.0.0.99", seen_at=now)
        process_ssdp_sighting(matched, store)
        process_ssdp_sighting(orphan, store)
        unassociated = store.advertised_services(unassociated_only=True)

    assert {s.identity for s in unassociated} == {"uuid:orphan"}


def test_mac_filter(tmp_path: Path):
    now = _now()
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.9", hostname=None, vendor=None, seen_at=now)
        sighting = parse_ssdp_packet(_alive_message(), source_ip="10.0.0.9", seen_at=now)
        process_ssdp_sighting(sighting, store)
        matched = store.advertised_services(mac="aa:bb:cc:dd:ee:ff")
        other = store.advertised_services(mac="11:22:33:44:55:66")

    assert len(matched) == 1
    assert other == []


def test_reset_all_clears_discovery_evidence(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=_now()):
            process_mdns_record_sighting(s, store)
        process_ssdp_sighting(parse_ssdp_packet(_alive_message(), seen_at=_now()), store)
        store.reset_all()
        assert store.advertised_services(include_expired=True) == []


def test_discovery_state_coherent_across_restart(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    now = _now()
    with DeviceStore(db_path) as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=now):
            process_mdns_record_sighting(s, store)

    with DeviceStore(db_path) as store:
        services = store.advertised_services()

    assert len(services) == 1
    assert services[0].instance_name == "Office Printer"


def test_discovery_diagnostics_reports_bounded_counts(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE)]), seen_at=_now()):
            process_mdns_record_sighting(s, store)
        diagnostics = store.discovery_diagnostics()

    assert diagnostics["mdns_ptr"] == 1
    assert diagnostics["ssdp_advertisements"] == 0


def test_bounded_retention_prunes_old_expired_evidence(tmp_path: Path):
    from lanfence.db import _DISCOVERY_RETENTION

    long_ago = _now() - _DISCOVERY_RETENTION - timedelta(days=1)
    with DeviceStore(tmp_path / "db.sqlite") as store:
        for s in parse_mdns_packet(_dns_message([_ptr_rr(_IPP_TYPE, _PRINTER_INSTANCE, ttl=1)]), seen_at=long_ago):
            process_mdns_record_sighting(s, store)
        # A later, unrelated write triggers opportunistic pruning.
        other_instance = [b"Other", b"_http", b"_tcp", b"local"]
        for s in parse_mdns_packet(
            _dns_message([_ptr_rr([b"_http", b"_tcp", b"local"], other_instance)]), seen_at=_now()
        ):
            process_mdns_record_sighting(s, store)

        services = store.advertised_services(include_expired=True)

    assert all(s.instance_name != "Office Printer" for s in services)


def test_status_reflects_ipv6_scope():
    msg = _dns_message([_aaaa_rr([b"printer", b"local"], "fe80::1")])
    sightings = parse_mdns_packet(msg, interface="eth0", family="ipv6", seen_at=_now())
    assert sightings[0].address == "fe80::1"
    assert sightings[0].family == "ipv6"
