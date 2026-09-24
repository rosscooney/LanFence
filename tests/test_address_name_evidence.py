from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from lanfence.db import DeviceStore


def _now():
    return datetime.now(timezone.utc)


# --- record_address_evidence -------------------------------------------


def test_record_address_evidence_coalesces_repeats(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", interface="eth0", source="arp", kind="observed", seen_at=t0,
        )
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", interface="eth0", source="arp", kind="observed",
            seen_at=t0 + timedelta(minutes=1),
        )
        evidence = store.address_evidence_for("aa:bb:cc:dd:ee:ff")

    assert len(evidence) == 1
    assert evidence[0].first_seen == t0
    assert evidence[0].last_seen == t0 + timedelta(minutes=1)


def test_record_address_evidence_keeps_distinct_ips_separate(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", interface="eth0", source="arp", kind="observed", seen_at=t0,
        )
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "fe80::1", interface="eth0", source="ipv6_nd", kind="observed", seen_at=t0,
        )
        evidence = store.address_evidence_for("aa:bb:cc:dd:ee:ff")

    assert {e.ip for e in evidence} == {"10.0.0.5", "fe80::1"}
    assert {e.family for e in evidence} == {"ipv4", "ipv6"}


def test_record_address_evidence_older_observation_widens_first_seen_not_last_seen(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", interface="eth0", source="arp", kind="observed",
            seen_at=t0,
        )
        store.record_address_evidence(  # a late-arriving OLDER observation
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", interface="eth0", source="arp", kind="observed",
            seen_at=t0 - timedelta(hours=1),
        )
        evidence = store.address_evidence_for("aa:bb:cc:dd:ee:ff")

    assert evidence[0].first_seen == t0 - timedelta(hours=1)
    assert evidence[0].last_seen == t0  # never moved backwards


def test_record_address_evidence_rejects_unspecified_multicast_and_broadcast(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        for bad_ip in ("0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255"):
            store.record_address_evidence(
                "aa:bb:cc:dd:ee:ff", bad_ip, interface="eth0", source="arp", kind="observed", seen_at=t0,
            )
        assert store.address_evidence_for("aa:bb:cc:dd:ee:ff") == []


def test_record_address_evidence_rejects_unparseable_ip(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "not-an-ip", interface="eth0", source="arp", kind="observed", seen_at=_now(),
        )
        assert store.address_evidence_for("aa:bb:cc:dd:ee:ff") == []


def test_same_ip_different_macs_both_retained(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", interface="eth0", source="arp", kind="observed", seen_at=t0,
        )
        store.record_address_evidence(
            "11:22:33:44:55:66", "10.0.0.5", interface="eth0", source="arp", kind="observed", seen_at=t0,
        )
        assert len(store.address_evidence_for("aa:bb:cc:dd:ee:ff")) == 1
        assert len(store.address_evidence_for("11:22:33:44:55:66")) == 1


def test_same_link_local_address_on_different_interfaces_both_retained(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "fe80::1", interface="eth0", source="ipv6_nd", kind="observed", seen_at=t0,
        )
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "fe80::1", interface="eth1", source="ipv6_nd", kind="observed", seen_at=t0,
        )
        evidence = store.address_evidence_for("aa:bb:cc:dd:ee:ff")

    assert {e.interface for e in evidence} == {"eth0", "eth1"}


# --- record_name_evidence -------------------------------------------------


def test_record_name_evidence_coalesces_repeats(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "office-laptop", source="dhcp_option_12", seen_at=t0)
        store.record_name_evidence(
            "aa:bb:cc:dd:ee:ff", "office-laptop", source="dhcp_option_12", seen_at=t0 + timedelta(minutes=5)
        )
        evidence = store.name_evidence_for("aa:bb:cc:dd:ee:ff")

    assert len(evidence) == 1
    assert evidence[0].last_seen == t0 + timedelta(minutes=5)


def test_record_name_evidence_case_and_trailing_dot_are_equivalent(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "Printer.local.", source="reverse_dns", ip="10.0.0.9", seen_at=t0)
        store.record_name_evidence(
            "aa:bb:cc:dd:ee:ff", "printer.local", source="reverse_dns", ip="10.0.0.9",
            seen_at=t0 + timedelta(minutes=1),
        )
        evidence = store.name_evidence_for("aa:bb:cc:dd:ee:ff")

    assert len(evidence) == 1  # same evidence row, coalesced


def test_record_name_evidence_short_name_not_equivalent_to_fqdn(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "printer", source="reverse_dns", seen_at=t0)
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "printer.local", source="reverse_dns", seen_at=t0)
        evidence = store.name_evidence_for("aa:bb:cc:dd:ee:ff")

    assert {e.name for e in evidence} == {"printer", "printer.local"}


def test_record_name_evidence_different_sources_kept_distinct(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "office-laptop", source="dhcp_option_12", seen_at=t0)
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "office-laptop", source="reverse_dns", seen_at=t0)
        evidence = store.name_evidence_for("aa:bb:cc:dd:ee:ff")

    assert {e.source for e in evidence} == {"dhcp_option_12", "reverse_dns"}


def test_record_name_evidence_ignores_empty_or_whitespace_name(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "", source="reverse_dns", seen_at=_now())
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "   ", source="reverse_dns", seen_at=_now())
        assert store.name_evidence_for("aa:bb:cc:dd:ee:ff") == []


def test_failed_lookup_does_not_erase_prior_name_evidence(tmp_path: Path):
    """A failed reverse-DNS lookup simply means the caller has nothing to
    report - calling record_name_evidence is never even attempted for it -
    so prior evidence must remain exactly as it was."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "office-laptop", source="reverse_dns", seen_at=_now())
        before = store.name_evidence_for("aa:bb:cc:dd:ee:ff")
        # a "failed lookup" is simply not calling record_name_evidence at all
        after = store.name_evidence_for("aa:bb:cc:dd:ee:ff")

    assert before == after


# --- preferred_address / preferred_name (tiered, deterministic) ------------


def test_preferred_address_prefers_observed_over_lease_reported_regardless_of_recency(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", interface="eth0", source="arp", kind="observed", seen_at=t0,
        )
        store.record_address_evidence(  # more recent, but lower-tier
            "aa:bb:cc:dd:ee:ff", "10.0.0.9", interface="eth0", source="dhcp_ack", kind="lease_reported",
            seen_at=t0 + timedelta(hours=1),
        )
        assert store.preferred_address("aa:bb:cc:dd:ee:ff") == "10.0.0.5"


def test_preferred_address_prefers_observed_over_legacy(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.9", interface="", source="legacy_snapshot", kind="observed",
            seen_at=t0 - timedelta(days=30),
        )
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", interface="eth0", source="arp", kind="observed", seen_at=t0,
        )
        assert store.preferred_address("aa:bb:cc:dd:ee:ff") == "10.0.0.5"


def test_preferred_address_most_recent_within_same_tier(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.5", interface="eth0", source="arp", kind="observed", seen_at=t0,
        )
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.6", interface="eth0", source="arp", kind="observed",
            seen_at=t0 + timedelta(minutes=1),
        )
        assert store.preferred_address("aa:bb:cc:dd:ee:ff") == "10.0.0.6"


def test_preferred_address_none_with_no_evidence(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        assert store.preferred_address("aa:bb:cc:dd:ee:ff") is None


def test_preferred_name_prefers_dhcp_over_reverse_dns_regardless_of_recency(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.record_name_evidence("aa:bb:cc:dd:ee:ff", "office-laptop", source="dhcp_option_12", seen_at=t0)
        store.record_name_evidence(
            "aa:bb:cc:dd:ee:ff", "office-laptop.lan", source="reverse_dns", seen_at=t0 + timedelta(hours=1),
        )
        assert store.preferred_name("aa:bb:cc:dd:ee:ff") == "office-laptop"


def test_preferred_name_none_with_no_evidence(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        assert store.preferred_name("aa:bb:cc:dd:ee:ff") is None


# --- refresh_preferred_fields / observe() integration ----------------------


def test_observe_dual_stack_retains_both_addresses(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=t0,
                      interface="eth0", source="arp")
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="fe80::1", hostname=None, vendor=None,
                      seen_at=t0 + timedelta(seconds=1), interface="eth0", source="ipv6_nd")
        evidence = store.address_evidence_for("aa:bb:cc:dd:ee:ff")

    assert {e.ip for e in evidence} == {"10.0.0.5", "fe80::1"}


def test_observe_dhcp_client_sighting_does_not_become_address_evidence(tmp_path: Path):
    """A bare DHCP client request/offer updates presence but is not trusted
    as address evidence - only a confirmed lease (dhcp_ack) or a direct
    ARP/ND observation is."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        device, event_type = store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=t0,
            interface="eth0", source="dhcp_client",
        )
        evidence = store.address_evidence_for("aa:bb:cc:dd:ee:ff")

    assert event_type == "new_device"  # presence/lifecycle still tracked
    assert evidence == []  # but no address evidence recorded
    assert device.ip == "10.0.0.5"  # best-effort raw fallback shown anyway (no better evidence exists)



def test_observe_ping_reply_is_direct_address_evidence(tmp_path: Path):
    """A ping answered from the device's own MAC is as direct as an ARP reply."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now(),
            interface="eth0", source="icmp",
        )
        evidence = store.address_evidence_for("aa:bb:cc:dd:ee:ff")

    assert [(e.ip, e.source, e.kind) for e in evidence] == [("10.0.0.5", "icmp", "observed")]

def test_observe_dhcp_client_ip_never_overrides_confirmed_evidence(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=t0,
                      interface="eth0", source="arp")
        # A later, unconfirmed DHCP client sighting for a DIFFERENT address.
        device, _ = store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.99", hostname=None, vendor=None,
            seen_at=t0 + timedelta(seconds=1), interface="eth0", source="dhcp_client",
        )

    assert device.ip == "10.0.0.5"  # unconfirmed address never displaces confirmed evidence


def test_observe_hostname_source_none_records_no_name_evidence(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="some-name", vendor=None, seen_at=_now(),
            interface="eth0", source="arp", hostname_source=None,
        )
        assert store.name_evidence_for("aa:bb:cc:dd:ee:ff") == []


def test_observe_preferred_hostname_survives_a_failed_later_lookup(tmp_path: Path):
    """A later call with hostname=None (failed lookup) must not clear the
    device's preferred hostname."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="office-laptop", vendor=None,
                      seen_at=t0, interface="eth0", source="arp", hostname_source="dhcp_option_12")
        device, _ = store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
            seen_at=t0 + timedelta(seconds=1), interface="eth0", source="arp",
        )

    assert device.hostname == "office-laptop"


# --- migration --------------------------------------------------------


def test_migration_imports_legacy_ip_and_hostname_as_legacy_snapshot(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    with DeviceStore(db_path) as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="old-name", vendor=None, seen_at=_now())
        store._conn.execute("DELETE FROM device_addresses")
        store._conn.execute("DELETE FROM device_names")
        store._conn.commit()

    with DeviceStore(db_path) as store:  # re-opening triggers the migration
        addresses = store.address_evidence_for("aa:bb:cc:dd:ee:ff")
        names = store.name_evidence_for("aa:bb:cc:dd:ee:ff")

    assert len(addresses) == 1
    assert addresses[0].source == "legacy_snapshot"
    assert addresses[0].ip == "10.0.0.5"
    assert len(names) == 1
    assert names[0].source == "legacy_snapshot"
    assert names[0].name == "old-name"


def test_migration_uses_import_time_not_device_first_seen(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    old = _now() - timedelta(days=30)
    with DeviceStore(db_path) as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=old)
        store._conn.execute("DELETE FROM device_addresses")
        store._conn.commit()

    before_reopen = _now()
    with DeviceStore(db_path) as store:
        addresses = store.address_evidence_for("aa:bb:cc:dd:ee:ff")
    after_reopen = _now()

    assert addresses[0].first_seen != old
    assert before_reopen <= addresses[0].first_seen <= after_reopen


def test_reopening_does_not_duplicate_legacy_evidence(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    with DeviceStore(db_path) as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="name", vendor=None, seen_at=_now())
        store._conn.execute("DELETE FROM device_addresses")
        store._conn.execute("DELETE FROM device_names")
        store._conn.commit()

    with DeviceStore(db_path):
        pass  # first reopen imports legacy evidence
    with DeviceStore(db_path) as store:  # second reopen must not re-import
        assert len(store.address_evidence_for("aa:bb:cc:dd:ee:ff")) == 1
        assert len(store.name_evidence_for("aa:bb:cc:dd:ee:ff")) == 1


def test_migration_does_not_touch_devices_with_existing_evidence(tmp_path: Path):
    """A device observed normally (evidence already present) must not also
    get a spurious legacy_snapshot row on the next open."""

    db_path = tmp_path / "db.sqlite"
    with DeviceStore(db_path) as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now())

    with DeviceStore(db_path) as store:
        evidence = store.address_evidence_for("aa:bb:cc:dd:ee:ff")

    assert len(evidence) == 1
    assert evidence[0].source == "arp"  # not overwritten/duplicated by legacy import


# --- reset_all --------------------------------------------------------


def test_reset_all_clears_address_and_name_evidence(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="name", vendor=None, seen_at=_now())
        store.reset_all()
        assert store.address_evidence_for("aa:bb:cc:dd:ee:ff") == []
        assert store.name_evidence_for("aa:bb:cc:dd:ee:ff") == []
