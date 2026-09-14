from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lanfence.db import DeviceStore
from lanfence.models import InspectedPort, InspectionResult


def _now():
    return datetime.now(timezone.utc)


def test_first_observation_is_new_device(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        device, event_type = store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", hostname="host1", vendor="Acme",
            seen_at=_now(),
        )
        assert event_type == "new_device"
        assert device.status == "online"
        assert device.mac == "aa:bb:cc:dd:ee:ff"


def test_repeated_observation_while_online_has_no_event(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.2.3.4", hostname=None, vendor=None, seen_at=t0)
        device, event_type = store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="1.2.3.4", hostname=None, vendor=None,
            seen_at=t0 + timedelta(seconds=30),
        )
        assert event_type is None
        assert device.status == "online"


def test_mark_offline_then_reappear(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.2.3.4", hostname=None, vendor=None, seen_at=t0)

        events = store.mark_offline(still_online_macs=set(), as_of=t0 + timedelta(minutes=1))
        assert len(events) == 1
        assert events[0].event_type == "disconnected"
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "offline"

        device, event_type = store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="1.2.3.4", hostname=None, vendor=None,
            seen_at=t0 + timedelta(minutes=2),
        )
        assert event_type == "reappeared"
        assert device.status == "online"


def test_mark_offline_leaves_still_online_devices_alone(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None, seen_at=t0)
        store.observe(mac="11:22:33:44:55:66", ip="2.2.2.2", hostname=None, vendor=None, seen_at=t0)

        events = store.mark_offline(still_online_macs={"aa:bb:cc:dd:ee:ff"}, as_of=t0)
        assert len(events) == 1
        assert events[0].mac == "11:22:33:44:55:66"
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"
        assert store.get_device("11:22:33:44:55:66").status == "offline"


def test_events_since_filters_by_time(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        old = _now() - timedelta(days=2)
        recent = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip=None, hostname=None, vendor=None, seen_at=old)
        store.observe(mac="11:22:33:44:55:66", ip=None, hostname=None, vendor=None, seen_at=recent)

        events = store.events_since(_now() - timedelta(hours=1))
        assert len(events) == 1
        assert events[0].mac == "11:22:33:44:55:66"


def test_all_devices_and_online_devices(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        # A real IPv4 address establishes discovery provenance (see
        # mark_offline) - ip=None would leave the device's coverage unknown
        # and mark_offline would conservatively skip it.
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None, seen_at=t0)
        store.observe(mac="11:22:33:44:55:66", ip="2.2.2.2", hostname=None, vendor=None, seen_at=t0)
        store.mark_offline(still_online_macs={"aa:bb:cc:dd:ee:ff"}, as_of=t0)

        assert len(store.all_devices()) == 2
        online = store.online_devices()
        assert len(online) == 1
        assert online[0].mac == "aa:bb:cc:dd:ee:ff"


def test_device_counts_matches_all_devices_and_online_devices(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        assert store.device_counts() == (0, 0)

        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None, seen_at=t0)
        store.observe(mac="11:22:33:44:55:66", ip="2.2.2.2", hostname=None, vendor=None, seen_at=t0)
        store.mark_offline(still_online_macs={"aa:bb:cc:dd:ee:ff"}, as_of=t0)

        known, online = store.device_counts()
        assert known == len(store.all_devices()) == 2
        assert online == len(store.online_devices()) == 1


def test_vendor_is_preserved_when_later_observation_has_none(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor="Acme", seen_at=t0)
        device, _ = store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None,
            seen_at=t0 + timedelta(seconds=1),
        )
        assert device.vendor == "Acme"


# --- due_for_alert (alert rate limiting) ------------------------------------


def test_due_for_alert_true_on_first_call(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        assert store.due_for_alert("aa:bb:cc:dd:ee:ff", "medium", now=_now(), cooldown_seconds=900) is True


def test_due_for_alert_false_within_cooldown_at_same_or_lower_severity(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        assert store.due_for_alert("aa:bb:cc:dd:ee:ff", "medium", now=t0, cooldown_seconds=900) is True
        # same severity, well within the cooldown
        assert store.due_for_alert(
            "aa:bb:cc:dd:ee:ff", "medium", now=t0 + timedelta(seconds=30), cooldown_seconds=900
        ) is False
        # lower severity, still within the cooldown
        assert store.due_for_alert(
            "aa:bb:cc:dd:ee:ff", "info", now=t0 + timedelta(seconds=30), cooldown_seconds=900
        ) is False


def test_due_for_alert_true_after_cooldown_elapses(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        assert store.due_for_alert("aa:bb:cc:dd:ee:ff", "medium", now=t0, cooldown_seconds=60) is True
        assert store.due_for_alert(
            "aa:bb:cc:dd:ee:ff", "medium", now=t0 + timedelta(seconds=61), cooldown_seconds=60
        ) is True


def test_due_for_alert_true_when_severity_escalates_within_cooldown(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        assert store.due_for_alert("aa:bb:cc:dd:ee:ff", "info", now=t0, cooldown_seconds=900) is True
        assert store.due_for_alert(
            "aa:bb:cc:dd:ee:ff", "high", now=t0 + timedelta(seconds=5), cooldown_seconds=900
        ) is True


def test_due_for_alert_zero_cooldown_always_true(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        assert store.due_for_alert("aa:bb:cc:dd:ee:ff", "high", now=t0, cooldown_seconds=0) is True
        assert store.due_for_alert(
            "aa:bb:cc:dd:ee:ff", "high", now=t0 + timedelta(seconds=1), cooldown_seconds=0
        ) is True


def test_due_for_alert_is_independent_per_mac(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        assert store.due_for_alert("aa:bb:cc:dd:ee:ff", "medium", now=t0, cooldown_seconds=900) is True
        assert store.due_for_alert("11:22:33:44:55:66", "medium", now=t0, cooldown_seconds=900) is True


# --- events_for --------------------------------------------------------


def test_events_for_filters_by_mac_and_time(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None, seen_at=t0)
        store.observe(mac="11:22:33:44:55:66", ip="2.2.2.2", hostname=None, vendor=None, seen_at=t0)
        store.mark_offline(set(), as_of=t0 + timedelta(minutes=1))
        store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None,
            seen_at=t0 + timedelta(minutes=2),
        )

        events = store.events_for("aa:bb:cc:dd:ee:ff")
        assert [e.event_type for e in events] == ["new_device", "disconnected", "reappeared"]
        assert all(e.mac == "aa:bb:cc:dd:ee:ff" for e in events)

        recent = store.events_for("aa:bb:cc:dd:ee:ff", since=t0 + timedelta(minutes=1, seconds=30))
        assert [e.event_type for e in recent] == ["reappeared"]


def test_events_for_unknown_mac_is_empty(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        assert store.events_for("aa:bb:cc:dd:ee:ff") == []


def test_events_for_normalizes_mac_case(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None, seen_at=_now())
        events = store.events_for("AA:BB:CC:DD:EE:FF")
        assert len(events) == 1


# --- review state (snooze / investigate / clear) ----------------------------


def test_get_review_defaults_to_pending_for_unknown_mac(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        review = store.get_review("aa:bb:cc:dd:ee:ff")
        assert review.state == "pending"
        assert review.notes is None
        assert review.snoozed_until is None
        assert review.updated_at is None


def test_set_snoozed_persists_state_and_expiry(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        until = now + timedelta(hours=24)
        store.set_snoozed("aa:bb:cc:dd:ee:ff", until=until, updated_at=now)
        review = store.get_review("aa:bb:cc:dd:ee:ff")
        assert review.state == "snoozed"
        assert review.snoozed_until == until
        assert review.updated_at == now


def test_set_snoozed_preserves_existing_notes_when_not_given(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_investigating("aa:bb:cc:dd:ee:ff", notes="original notes", updated_at=now)
        store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now + timedelta(hours=1), updated_at=now)
        assert store.get_review("aa:bb:cc:dd:ee:ff").notes == "original notes"


def test_set_snoozed_overwrites_notes_when_given(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_investigating("aa:bb:cc:dd:ee:ff", notes="old", updated_at=now)
        store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now + timedelta(hours=1), notes="new", updated_at=now)
        assert store.get_review("aa:bb:cc:dd:ee:ff").notes == "new"


def test_set_investigating_clears_any_snooze(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now + timedelta(hours=1), updated_at=now)
        store.set_investigating("aa:bb:cc:dd:ee:ff", notes="check it", updated_at=now)
        review = store.get_review("aa:bb:cc:dd:ee:ff")
        assert review.state == "investigating"
        assert review.snoozed_until is None
        assert review.notes == "check it"


def test_clear_review_resets_to_pending(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_investigating("aa:bb:cc:dd:ee:ff", notes="x", updated_at=now)
        store.clear_review("aa:bb:cc:dd:ee:ff")
        review = store.get_review("aa:bb:cc:dd:ee:ff")
        assert review.state == "pending"
        assert review.notes is None
        assert review.updated_at is None


def test_clear_review_on_never_reviewed_mac_is_a_noop(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.clear_review("aa:bb:cc:dd:ee:ff")  # must not raise
        assert store.get_review("aa:bb:cc:dd:ee:ff").state == "pending"


def test_is_snoozed_true_within_window_false_after_expiry(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now + timedelta(hours=1), updated_at=now)
        assert store.is_snoozed("aa:bb:cc:dd:ee:ff", now=now) is True
        assert store.is_snoozed("aa:bb:cc:dd:ee:ff", now=now + timedelta(hours=2)) is False


def test_is_snoozed_false_for_pending_or_investigating(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        assert store.is_snoozed("aa:bb:cc:dd:ee:ff", now=now) is False
        store.set_investigating("aa:bb:cc:dd:ee:ff", updated_at=now)
        assert store.is_snoozed("aa:bb:cc:dd:ee:ff", now=now) is False


def test_review_state_persists_across_reopening_the_database(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    now = _now()
    with DeviceStore(db_path) as store:
        store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now + timedelta(hours=1), notes="reopened test", updated_at=now)

    with DeviceStore(db_path) as store:
        review = store.get_review("aa:bb:cc:dd:ee:ff")
        assert review.state == "snoozed"
        assert review.notes == "reopened test"


def test_device_review_table_added_to_a_pre_existing_database_without_it(tmp_path: Path):
    """Migration test: a database file created before device_review existed
    (here, simulated by dropping the table after normal creation) gets it
    back transparently - and without data loss - the next time it's opened,
    since the schema is applied with CREATE TABLE IF NOT EXISTS."""

    db_path = tmp_path / "db.sqlite"
    now = _now()
    with DeviceStore(db_path) as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None, seen_at=now)
        store._conn.execute("DROP TABLE device_review")
        store._conn.commit()

    with DeviceStore(db_path) as store:  # re-opening should recreate the table
        assert store.get_review("aa:bb:cc:dd:ee:ff").state == "pending"
        # pre-existing data untouched by the migration
        assert store.get_device("aa:bb:cc:dd:ee:ff") is not None
        store.set_investigating("aa:bb:cc:dd:ee:ff", notes="works after migration", updated_at=now)
        assert store.get_review("aa:bb:cc:dd:ee:ff").notes == "works after migration"


# --- offline grace period / missed-scan tracking (mark_offline) ------------


def _observe_ipv4(store, mac, *, ip="10.0.0.5", seen_at, interface="eth0", subnet="10.0.0.0/24"):
    return store.observe(
        mac=mac, ip=ip, hostname=None, vendor=None, seen_at=seen_at,
        interface=interface, subnet=subnet,
    )


def test_mark_offline_single_miss_stays_online_with_grace_period(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=1),
            grace_seconds=180, missed_after=3, ipv4_covered=True, ipv4_subnet="10.0.0.0/24",
            interface="eth0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_mark_offline_threshold_reached_before_grace_period_stays_online(tmp_path: Path):
    """3 misses accumulate quickly, but the grace period (elapsed time since
    last_seen) hasn't been reached yet - both conditions must hold."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        kwargs = dict(grace_seconds=180, missed_after=3, ipv4_covered=True,
                      ipv4_subnet="10.0.0.0/24", interface="eth0")
        store.mark_offline(set(), as_of=t0 + timedelta(seconds=1), **kwargs)
        store.mark_offline(set(), as_of=t0 + timedelta(seconds=2), **kwargs)
        events = store.mark_offline(set(), as_of=t0 + timedelta(seconds=3), **kwargs)

        assert events == []  # 3rd miss reached, but only 3 seconds elapsed < 180s grace
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_mark_offline_grace_period_elapses_before_threshold_stays_online(tmp_path: Path):
    """Plenty of time has passed, but only 1 of the required 3 misses has
    happened - both conditions must hold."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=999),
            grace_seconds=180, missed_after=3, ipv4_covered=True,
            ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_mark_offline_both_conditions_satisfied_at_exact_boundary(tmp_path: Path):
    """Exactly missed_after misses AND exactly grace_seconds elapsed - both
    "reaches the threshold" conditions are inclusive (>=)."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        kwargs = dict(grace_seconds=180, missed_after=3, ipv4_covered=True,
                      ipv4_subnet="10.0.0.0/24", interface="eth0")
        store.mark_offline(set(), as_of=t0 + timedelta(seconds=60), **kwargs)
        store.mark_offline(set(), as_of=t0 + timedelta(seconds=120), **kwargs)
        # 3rd miss, exactly 180s after last_seen (t0) - both boundaries hit exactly.
        events = store.mark_offline(set(), as_of=t0 + timedelta(seconds=180), **kwargs)

        assert len(events) == 1
        assert events[0].event_type == "disconnected"
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "offline"


def test_mark_offline_compat_zero_seconds_one_miss_disconnects_immediately(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        events = store.mark_offline(
            set(), as_of=t0, grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert len(events) == 1
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "offline"


def test_active_sighting_resets_missed_scan_count(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)
        kwargs = dict(grace_seconds=0, missed_after=3, ipv4_covered=True,
                      ipv4_subnet="10.0.0.0/24", interface="eth0")

        store.mark_offline(set(), as_of=t0 + timedelta(seconds=1), **kwargs)  # miss 1 of 3
        store.mark_offline(set(), as_of=t0 + timedelta(seconds=2), **kwargs)  # miss 2 of 3
        # Re-sighted - resets the count back to zero.
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0 + timedelta(seconds=3))
        # Only 1 miss since the reset - must not disconnect even though 2+1=3.
        events = store.mark_offline(set(), as_of=t0 + timedelta(seconds=4), **kwargs)

        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_passive_sighting_resets_missed_scan_count(tmp_path: Path):
    """A passive (not active-scan) observe() call is just as good at
    resetting the counter as an active one - observe() doesn't distinguish."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)
        kwargs = dict(grace_seconds=0, missed_after=2, ipv4_covered=True,
                      ipv4_subnet="10.0.0.0/24", interface="eth0")

        store.mark_offline(set(), as_of=t0 + timedelta(seconds=1), **kwargs)  # miss 1 of 2
        # A passive sighting arrives between sweeps (no interface/subnet -
        # a passive ARP capture has no "subnet swept" concept).
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
                      seen_at=t0 + timedelta(seconds=2))
        events = store.mark_offline(set(), as_of=t0 + timedelta(seconds=3), **kwargs)

        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_disconnected_then_reappeared_each_emit_exactly_once(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=1), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert [e.event_type for e in events] == ["disconnected"]

        _, event_type = _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0 + timedelta(seconds=2))
        assert event_type == "reappeared"

        all_events = store.events_for("aa:bb:cc:dd:ee:ff")
        assert [e.event_type for e in all_events] == ["new_device", "disconnected", "reappeared"]


def test_mark_offline_does_not_advance_last_seen(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        store.mark_offline(
            set(), as_of=t0 + timedelta(hours=5), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        device = store.get_device("aa:bb:cc:dd:ee:ff")
        assert device.status == "offline"
        assert device.last_seen == t0  # NOT advanced to the "as_of" confirmation time


def test_observe_guards_against_older_sighting_moving_last_seen_backwards(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="new-name", vendor=None, seen_at=t0)
        device, event_type = store.observe(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.9", hostname="stale-name", vendor=None,
            seen_at=t0 - timedelta(seconds=30),
        )
        assert event_type is None  # still just a routine refresh, not a new lifecycle event
        assert device.last_seen == t0
        assert device.ip == "10.0.0.5"
        assert device.hostname == "new-name"


def test_full_scan_failure_does_not_count_as_a_miss(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=999), grace_seconds=0, missed_after=1,
            ipv4_covered=False, ipv4_subnet=None, ipv6_covered=False, interface="eth0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_ipv4_scan_failure_does_not_disconnect_ipv4_only_device_despite_successful_ipv6(tmp_path: Path):
    """A successful IPv6 scan must not mark an IPv4-only device offline when
    IPv4 scanning failed - the IPv6 scan's success says nothing about a
    device this sweep never had a way to see."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=999), grace_seconds=0, missed_after=1,
            ipv4_covered=False, ipv4_subnet=None,  # IPv4 scan failed this sweep
            ipv6_covered=True,  # succeeded, but irrelevant to an IPv4-only device
            interface="eth0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_ipv6_scan_failure_does_not_disconnect_ipv6_only_device_despite_successful_ipv4(tmp_path: Path):
    """The mirror image: a successful IPv4 scan must not mark an IPv6-only
    device offline when IPv6 scanning failed."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="fe80::1", hostname=None, vendor=None,
                      seen_at=t0, interface="eth0")

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=999), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24",  # succeeded, but irrelevant to an IPv6-only device
            ipv6_covered=False,  # IPv6 scan failed this sweep
            interface="eth0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_ipv4_only_device_disconnects_when_its_own_family_succeeds(tmp_path: Path):
    """The positive-case complement: an IPv4-only device's own family
    succeeding is sufficient, regardless of an unrelated IPv6 failure."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=999), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24",
            ipv6_covered=False,  # IPv6 scan failed this sweep - irrelevant to an IPv4-only device
            interface="eth0",
        )
        assert len(events) == 1
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "offline"


def test_successful_empty_scan_is_eligible_evidence_of_absence(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=999), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert len(events) == 1
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "offline"


def test_scan_of_a_different_subnet_does_not_disconnect_the_device(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0, subnet="10.0.0.0/24")

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=999), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="192.168.1.0/24",  # a different network was scanned
            interface="eth0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_scan_on_a_different_interface_does_not_disconnect_the_device(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0, interface="eth0")

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=999), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="wlan0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


def test_device_observed_via_both_families_requires_both_covered(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
                      seen_at=t0, interface="eth0", subnet="10.0.0.0/24")
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="fe80::1", hostname=None, vendor=None,
                      seen_at=t0, interface="eth0")

        # Only IPv4 covered this sweep - IPv6 path unconfirmed, so no miss counted.
        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=999), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", ipv6_covered=False, interface="eth0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"

        # Both covered now - the miss is eligible.
        events = store.mark_offline(
            set(), as_of=t0 + timedelta(seconds=1000), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", ipv6_covered=True, interface="eth0",
        )
        assert len(events) == 1
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "offline"


def test_legacy_record_with_no_provenance_is_left_alone(tmp_path: Path):
    """A device row from before this feature (missed_scans/seen_via_ipv4/
    seen_via_ipv6/last_interface/ipv4_subnet all at their migration
    defaults) must be treated conservatively - never counted as missed -
    until a fresh sighting establishes real coverage."""

    db_path = tmp_path / "db.sqlite"
    t0 = _now()
    with DeviceStore(db_path) as store:
        store._conn.execute(
            "INSERT INTO devices (mac, ip, hostname, vendor, status, first_seen, last_seen) "
            "VALUES ('aa:bb:cc:dd:ee:ff', '10.0.0.5', NULL, NULL, 'online', ?, ?)",
            (t0.isoformat(), t0.isoformat()),
        )
        store._conn.commit()

        events = store.mark_offline(
            set(), as_of=t0 + timedelta(days=1), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"

        # A fresh sighting establishes coverage; now absence can be detected.
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0 + timedelta(days=1))
        events = store.mark_offline(
            set(), as_of=t0 + timedelta(days=1, seconds=1), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert len(events) == 1
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "offline"


def test_missed_scan_state_persists_across_reopening_the_database(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    t0 = _now()
    kwargs = dict(grace_seconds=0, missed_after=3, ipv4_covered=True,
                  ipv4_subnet="10.0.0.0/24", interface="eth0")

    with DeviceStore(db_path) as store:
        _observe_ipv4(store, "aa:bb:cc:dd:ee:ff", seen_at=t0)
        store.mark_offline(set(), as_of=t0 + timedelta(seconds=1), **kwargs)  # miss 1 of 3

    with DeviceStore(db_path) as store:  # simulates a monitor restart
        store.mark_offline(set(), as_of=t0 + timedelta(seconds=2), **kwargs)  # miss 2 of 3
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"
        events = store.mark_offline(set(), as_of=t0 + timedelta(seconds=3), **kwargs)  # miss 3 of 3
        assert len(events) == 1
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "offline"


def test_devices_table_migration_adds_offline_tracking_columns(tmp_path: Path):
    """A database created before this feature (no missed_scans/seen_via_*/
    last_interface/ipv4_subnet columns) gets them idempotently, without
    losing existing device rows."""

    db_path = tmp_path / "db.sqlite"
    t0 = _now()
    with DeviceStore(db_path) as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=t0)
        # Simulate a pre-feature database by rebuilding `devices` without the
        # new columns, preserving the pre-existing row.
        store._conn.executescript(
            """
            CREATE TABLE devices_old (
                mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT,
                status TEXT NOT NULL DEFAULT 'online',
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
            );
            INSERT INTO devices_old SELECT mac, ip, hostname, vendor, status, first_seen, last_seen FROM devices;
            DROP TABLE devices;
            ALTER TABLE devices_old RENAME TO devices;
            """
        )
        store._conn.commit()

    with DeviceStore(db_path) as store:  # re-opening should add the missing columns
        device = store.get_device("aa:bb:cc:dd:ee:ff")
        assert device is not None
        assert device.status == "online"
        # legacy row has no provenance yet - mark_offline must leave it alone
        events = store.mark_offline(
            set(), as_of=t0 + timedelta(days=1), grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert events == []
        assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"


# --- reset_all -----------------------------------------------------------


def test_reset_all_clears_devices_events_alerts_and_review(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=t0)
        store.observe(mac="11:22:33:44:55:66", ip="10.0.0.6", hostname=None, vendor=None, seen_at=t0)
        store.due_for_alert("aa:bb:cc:dd:ee:ff", "high", now=t0, cooldown_seconds=900)
        store.set_investigating("11:22:33:44:55:66", notes="hmm", updated_at=t0)

        store.reset_all()

        assert store.all_devices() == []
        assert store.events_since(t0 - timedelta(days=1)) == []
        assert store.due_for_alert("aa:bb:cc:dd:ee:ff", "high", now=t0, cooldown_seconds=900) is True
        assert store.get_review("11:22:33:44:55:66").state == "pending"


def test_reset_all_on_empty_database_is_a_noop(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.reset_all()  # must not raise
        assert store.all_devices() == []


# --- active inspection results ----------------------------------------------


def _inspection(**overrides) -> InspectionResult:
    base = dict(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", method="socket", observed_at=_now(),
        open_ports=[InspectedPort(port=22, service="ssh"), InspectedPort(port=80, service="http", banner="nginx")],
        platform_guess="Linux/Unix-like device (SSH only)", platform_confidence="low",
        platform_reasons=["Open port: 22 (SSH), nothing else responded"],
    )
    base.update(overrides)
    return InspectionResult(**base)


def test_inspection_for_unknown_mac_is_none(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        assert store.inspection_for("aa:bb:cc:dd:ee:ff") is None


def test_record_and_read_back_inspection_result(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        result = _inspection()
        store.record_inspection(result)
        fetched = store.inspection_for("aa:bb:cc:dd:ee:ff")
        assert fetched == result


def test_record_inspection_replaces_rather_than_accumulates(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.record_inspection(_inspection(method="socket"))
        store.record_inspection(_inspection(method="nmap", open_ports=[InspectedPort(port=443, service="https")]))
        fetched = store.inspection_for("aa:bb:cc:dd:ee:ff")
        assert fetched.method == "nmap"
        assert [p.port for p in fetched.open_ports] == [443]


def test_reset_all_clears_inspection_results(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        store.record_inspection(_inspection())
        store.reset_all()
        assert store.inspection_for("aa:bb:cc:dd:ee:ff") is None


# --- presence policy -------------------------------------------------------


def test_get_presence_defaults_to_unspecified_for_unknown_mac(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        presence = store.get_presence("aa:bb:cc:dd:ee:ff")
        assert presence.policy == "unspecified"
        assert presence.offline_after_seconds is None
        assert presence.availability_alerted is False
        assert presence.updated_at is None


def test_set_presence_policy_persists(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "intermittent", updated_at=now)
        presence = store.get_presence("aa:bb:cc:dd:ee:ff")
        assert presence.policy == "intermittent"
        assert presence.updated_at == now


def test_set_offline_after_only_meaningful_for_always_on_but_stored_regardless(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=now)
        store.set_offline_after("aa:bb:cc:dd:ee:ff", 600.0, updated_at=now)
        presence = store.get_presence("aa:bb:cc:dd:ee:ff")
        assert presence.policy == "always-on"
        assert presence.offline_after_seconds == 600.0


def test_moving_away_from_always_on_clears_override_and_alerted_flag(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=now)
        store.set_offline_after("aa:bb:cc:dd:ee:ff", 600.0, updated_at=now)
        store.set_availability_alerted("aa:bb:cc:dd:ee:ff", True, updated_at=now)

        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "intermittent", updated_at=now)
        presence = store.get_presence("aa:bb:cc:dd:ee:ff")
        assert presence.policy == "intermittent"
        assert presence.offline_after_seconds is None
        assert presence.availability_alerted is False


def test_switching_back_to_always_on_keeps_previous_override(tmp_path: Path):
    """Re-affirming the *same* always-on policy (not switching away and
    back) preserves whatever override/alerted state was already there."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=now)
        store.set_offline_after("aa:bb:cc:dd:ee:ff", 600.0, updated_at=now)
        store.set_availability_alerted("aa:bb:cc:dd:ee:ff", True, updated_at=now)

        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=now)
        presence = store.get_presence("aa:bb:cc:dd:ee:ff")
        assert presence.offline_after_seconds == 600.0
        assert presence.availability_alerted is True


def test_reset_all_clears_presence_policy(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=now)
        store.reset_all()
        assert store.get_presence("aa:bb:cc:dd:ee:ff").policy == "unspecified"


def test_device_presence_table_added_to_a_pre_existing_database(tmp_path: Path):
    """Migration test: a database created before presence policies existed
    gets the device_presence table transparently, without data loss."""

    db_path = tmp_path / "db.sqlite"
    now = _now()
    with DeviceStore(db_path) as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        store._conn.execute("DROP TABLE device_presence")
        store._conn.commit()

    with DeviceStore(db_path) as store:  # re-opening should recreate the table
        assert store.get_presence("aa:bb:cc:dd:ee:ff").policy == "unspecified"
        assert store.get_device("aa:bb:cc:dd:ee:ff") is not None
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "intermittent", updated_at=now)
        assert store.get_presence("aa:bb:cc:dd:ee:ff").policy == "intermittent"


# --- evaluate_availability --------------------------------------------------


def _offline_always_on(store: DeviceStore, mac: str, *, last_seen, offline_after=None):
    store.observe(mac=mac, ip="10.0.0.5", hostname=None, vendor=None, seen_at=last_seen,
                  interface="eth0", subnet="10.0.0.0/24")
    store.mark_offline(
        set(), as_of=last_seen, grace_seconds=0, missed_after=1,
        ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
    )
    store.set_presence_policy(mac, "always-on", updated_at=last_seen)
    if offline_after is not None:
        store.set_offline_after(mac, offline_after, updated_at=last_seen)


def test_evaluate_availability_fires_once_duration_reached(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _offline_always_on(store, "aa:bb:cc:dd:ee:ff", last_seen=t0)

        due = store.evaluate_availability(
            as_of=t0 + timedelta(seconds=600), default_offline_after_seconds=300,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert [d["mac"] for d in due] == ["aa:bb:cc:dd:ee:ff"]
        assert store.get_presence("aa:bb:cc:dd:ee:ff").availability_alerted is True


def test_evaluate_availability_not_yet_due(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _offline_always_on(store, "aa:bb:cc:dd:ee:ff", last_seen=t0)

        due = store.evaluate_availability(
            as_of=t0 + timedelta(seconds=10), default_offline_after_seconds=300,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert due == []
        assert store.get_presence("aa:bb:cc:dd:ee:ff").availability_alerted is False


def test_evaluate_availability_never_fires_twice_for_the_same_episode(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _offline_always_on(store, "aa:bb:cc:dd:ee:ff", last_seen=t0)
        kwargs = dict(default_offline_after_seconds=300, ipv4_covered=True,
                      ipv4_subnet="10.0.0.0/24", interface="eth0")

        first = store.evaluate_availability(as_of=t0 + timedelta(seconds=600), **kwargs)
        second = store.evaluate_availability(as_of=t0 + timedelta(seconds=1200), **kwargs)
        assert len(first) == 1
        assert second == []  # already alerted - not re-fired on a later sweep


def test_evaluate_availability_alerted_flag_survives_reopening_the_database(tmp_path: Path):
    """Persistence test: a restarted monitor (a fresh DeviceStore handle)
    must not re-fire an absence alert that already fired before the
    restart."""

    db_path = tmp_path / "db.sqlite"
    t0 = _now()
    kwargs = dict(default_offline_after_seconds=300, ipv4_covered=True,
                  ipv4_subnet="10.0.0.0/24", interface="eth0")

    with DeviceStore(db_path) as store:
        _offline_always_on(store, "aa:bb:cc:dd:ee:ff", last_seen=t0)
        due = store.evaluate_availability(as_of=t0 + timedelta(seconds=600), **kwargs)
        assert len(due) == 1

    with DeviceStore(db_path) as store:  # simulates a monitor restart
        due_again = store.evaluate_availability(as_of=t0 + timedelta(seconds=1200), **kwargs)
        assert due_again == []
        assert store.get_presence("aa:bb:cc:dd:ee:ff").availability_alerted is True


def test_evaluate_availability_uses_per_device_override(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _offline_always_on(store, "aa:bb:cc:dd:ee:ff", last_seen=t0, offline_after=60)

        # Global default (300s) hasn't been reached, but the override (60s) has.
        due = store.evaluate_availability(
            as_of=t0 + timedelta(seconds=90), default_offline_after_seconds=300,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert len(due) == 1


def test_evaluate_availability_ignores_non_always_on_devices(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
                      seen_at=t0, interface="eth0", subnet="10.0.0.0/24")
        store.mark_offline(
            set(), as_of=t0, grace_seconds=0, missed_after=1,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        # presence left at the default "unspecified"

        due = store.evaluate_availability(
            as_of=t0 + timedelta(days=1), default_offline_after_seconds=300,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert due == []


def test_evaluate_availability_respects_coverage_rules(tmp_path: Path):
    """A sweep on a different subnet must not evaluate this device's
    absence - same conservative coverage rule as mark_offline."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        _offline_always_on(store, "aa:bb:cc:dd:ee:ff", last_seen=t0)

        due = store.evaluate_availability(
            as_of=t0 + timedelta(seconds=600), default_offline_after_seconds=300,
            ipv4_covered=True, ipv4_subnet="192.168.1.0/24", interface="eth0",
        )
        assert due == []


def test_evaluate_availability_still_online_device_is_not_a_candidate(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
                      seen_at=t0, interface="eth0", subnet="10.0.0.0/24")
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=t0)

        due = store.evaluate_availability(
            as_of=t0 + timedelta(days=1), default_offline_after_seconds=300,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert due == []


# --- due_for_alert key override ---------------------------------------------


def test_due_for_alert_independent_keys_do_not_interfere(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        assert store.due_for_alert(
            "aa:bb:cc:dd:ee:ff", "medium", now=t0, cooldown_seconds=900,
            key="aa:bb:cc:dd:ee:ff#availability#medium",
        ) is True
        # A different key for the same MAC is unaffected by the above.
        assert store.due_for_alert(
            "aa:bb:cc:dd:ee:ff", "info", now=t0, cooldown_seconds=900,
            key="aa:bb:cc:dd:ee:ff#availability#info",
        ) is True


def test_discovery_writes_release_lock_and_commit_retention(tmp_path: Path):
    """An idle discovery monitor must not block reset or another monitor."""
    import sqlite3

    path = tmp_path / "db.sqlite"
    now = _now()
    with DeviceStore(path) as monitor:
        writes = [
            lambda when: monitor.record_mdns_ptr(
                interface="eth0", service_type="_http._tcp.local", instance_name="web",
                fq_instance="web._http._tcp.local", ttl=60, seen_at=when,
                source_ip="192.168.1.2", source_mac="aa:bb:cc:dd:ee:ff"),
            lambda when: monitor.record_mdns_srv(
                interface="eth0", fq_instance="web._http._tcp.local",
                target_host="web.local", port=80, ttl=60, seen_at=when),
            lambda when: monitor.record_mdns_txt(
                interface="eth0", fq_instance="web._http._tcp.local",
                attributes={}, ttl=60, seen_at=when),
            lambda when: monitor.record_mdns_addr(
                interface="eth0", target_host="web.local", family="ipv4",
                ip="192.168.1.2", ttl=60, seen_at=when),
            lambda when: monitor.record_ssdp_advertisement(
                interface="eth0", usn="uuid:test", nt_or_st="upnp:rootdevice",
                server=None, location=None, max_age=60, boot_id=None, config_id=None,
                seen_at=when, source_ip="192.168.1.2",
                source_mac="aa:bb:cc:dd:ee:ff", family="ipv4"),
        ]
        for write in writes:
            # Seed expired evidence in another table, so cleanup must persist.
            monitor.record_mdns_txt(
                interface="eth0", fq_instance="old._http._tcp.local",
                attributes={}, ttl=1, seen_at=now - timedelta(days=31))
            write(now)
            with sqlite3.connect(path, timeout=0) as observer:
                observer.execute("BEGIN IMMEDIATE")
                assert observer.execute(
                    "SELECT COUNT(*) FROM mdns_txt WHERE fq_instance = ?",
                    ("old._http._tcp.local",),
                ).fetchone()[0] == 0
            # Repeat/upsert paths must release the lock too.
            write(now + timedelta(seconds=1))
            assert not monitor._conn.in_transaction
            with DeviceStore(path) as command:
                command.reset_all()
            with DeviceStore(path) as restarted:
                assert restarted.device_counts() == (0, 0)


# --- global alert-dispatch budget -------------------------------------------


def test_consume_global_alert_budget_allows_up_to_the_max_per_window(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        results = [
            store.consume_global_alert_budget(now, max_per_window=3, window_seconds=60)
            for _ in range(5)
        ]
        assert results == [True, True, True, False, False]


def test_consume_global_alert_budget_defeats_mac_rotation_style_flooding(tmp_path: Path):
    """A per-MAC cooldown alone can't bound total alert volume when every
    finding comes from a distinct (e.g. randomized) MAC - each is
    individually "new". The global budget must still cap total volume
    regardless of how many distinct identities are involved."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        allowed = 0
        for i in range(50):
            mac = f"aa:bb:cc:dd:ee:{i:02x}"
            # Each MAC's own per-device cooldown independently allows it
            # (due_for_alert has never seen this key before) ...
            assert store.due_for_alert(mac, "medium", now=now, cooldown_seconds=900) is True
            # ... but the shared global budget still caps total volume.
            if store.consume_global_alert_budget(now, max_per_window=10, window_seconds=60):
                allowed += 1
        assert allowed == 10


def test_consume_global_alert_budget_resets_after_window_elapses(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        for _ in range(3):
            assert store.consume_global_alert_budget(now, max_per_window=3, window_seconds=60) is True
        assert store.consume_global_alert_budget(now, max_per_window=3, window_seconds=60) is False

        later = now + timedelta(seconds=61)
        assert store.consume_global_alert_budget(later, max_per_window=3, window_seconds=60) is True


def test_consume_global_alert_budget_disabled_when_max_is_zero(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        assert all(
            store.consume_global_alert_budget(now, max_per_window=0, window_seconds=60) for _ in range(20)
        )


def test_reset_all_clears_global_alert_budget(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        for _ in range(3):
            store.consume_global_alert_budget(now, max_per_window=3, window_seconds=60)
        assert store.consume_global_alert_budget(now, max_per_window=3, window_seconds=60) is False
        store.reset_all()
        assert store.consume_global_alert_budget(now, max_per_window=3, window_seconds=60) is True


# --- SMS segment budget ------------------------------------------------------


def test_consume_sms_budget_allows_up_to_the_daily_cap(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        assert store.consume_sms_budget(50, now=now, max_segments_per_day=100) is True
        assert store.consume_sms_budget(40, now=now, max_segments_per_day=100) is True
        assert store.consume_sms_budget(20, now=now, max_segments_per_day=100) is False  # only 10 left
        assert store.consume_sms_budget(10, now=now, max_segments_per_day=100) is True


def test_consume_sms_budget_disabled_when_max_is_zero(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        assert store.consume_sms_budget(10_000, now=now, max_segments_per_day=0) is True


def test_consume_sms_budget_is_scoped_per_calendar_day(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        day1 = datetime(2026, 1, 1, 23, 0, tzinfo=timezone.utc)
        day2 = datetime(2026, 1, 2, 0, 30, tzinfo=timezone.utc)
        assert store.consume_sms_budget(80, now=day1, max_segments_per_day=100) is True
        assert store.consume_sms_budget(80, now=day1, max_segments_per_day=100) is False
        # A new UTC calendar day gets a fresh budget.
        assert store.consume_sms_budget(80, now=day2, max_segments_per_day=100) is True


def test_consume_sms_budget_survives_a_simulated_restart(tmp_path: Path):
    """A restart (a fresh DeviceStore instance against the same file) must
    not reopen today's already-spent SMS budget."""

    db_path = tmp_path / "db.sqlite"
    now = _now()
    with DeviceStore(db_path) as store:
        assert store.consume_sms_budget(90, now=now, max_segments_per_day=100) is True

    with DeviceStore(db_path) as restarted:
        assert restarted.consume_sms_budget(20, now=now, max_segments_per_day=100) is False
        assert restarted.consume_sms_budget(10, now=now, max_segments_per_day=100) is True


def test_reset_all_does_not_clear_sms_budget(tmp_path: Path):
    """The SMS budget is a cost-safety guardrail, not device inventory -
    lanfence reset must not be usable as a way to reopen it."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        assert store.consume_sms_budget(100, now=now, max_segments_per_day=100) is True
        store.reset_all()
        assert store.consume_sms_budget(1, now=now, max_segments_per_day=100) is False


# --- retention caps on attacker-controlled evidence -------------------------


def test_evidence_row_cap_prunes_oldest_address_evidence_per_mac(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite", max_evidence_rows_per_mac=5) as store:
        now = _now()
        for i in range(20):
            store.record_address_evidence(
                "aa:bb:cc:dd:ee:ff", f"10.0.0.{i}", interface="eth0", source="arp",
                kind="observed", seen_at=now + timedelta(seconds=i),
            )
        rows = store.address_evidence_for("aa:bb:cc:dd:ee:ff")
        assert len(rows) == 5
        # The most recently seen rows are the ones kept.
        assert {r.ip for r in rows} == {f"10.0.0.{i}" for i in range(15, 20)}


def test_evidence_row_cap_prunes_oldest_name_evidence_per_mac(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite", max_evidence_rows_per_mac=3) as store:
        now = _now()
        for i in range(10):
            store.record_name_evidence(
                "aa:bb:cc:dd:ee:ff", f"host-{i}", source="dhcp_option_12", seen_at=now + timedelta(seconds=i),
            )
        rows = store.name_evidence_for("aa:bb:cc:dd:ee:ff")
        assert len(rows) == 3


def test_evidence_row_cap_is_independent_per_mac(tmp_path: Path):
    """One MAC hitting its cap must never evict another MAC's evidence."""

    with DeviceStore(tmp_path / "db.sqlite", max_evidence_rows_per_mac=2) as store:
        now = _now()
        for i in range(10):
            store.record_address_evidence(
                "aa:bb:cc:dd:ee:ff", f"10.0.0.{i}", interface="eth0", source="arp",
                kind="observed", seen_at=now + timedelta(seconds=i),
            )
        store.record_address_evidence(
            "11:22:33:44:55:66", "10.0.1.1", interface="eth0", source="arp",
            kind="observed", seen_at=now,
        )
        assert len(store.address_evidence_for("aa:bb:cc:dd:ee:ff")) == 2
        assert len(store.address_evidence_for("11:22:33:44:55:66")) == 1


def test_dhcp_server_findings_cap_prunes_oldest(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite", max_dhcp_server_findings=3) as store:
        now = _now()
        for i in range(10):
            store.record_dhcp_server_finding(
                interface="eth0", server_id=f"10.0.0.{i}", observed_at=now + timedelta(seconds=i),
                approved_at_observation=False, message_type="OFFER", source_ip=f"10.0.0.{i}",
                source_mac=None, relay_ip=None, router=None, dns=None,
            )
        rows = store._conn.execute("SELECT COUNT(*) AS n FROM dhcp_server_findings").fetchone()["n"]
        assert rows == 3


def test_discovery_table_row_cap_prunes_oldest_unexpired_rows(tmp_path: Path):
    """A burst of many distinct, still-unexpired (not yet due for
    time-based pruning) fake advertisements must still be bounded."""

    with DeviceStore(tmp_path / "db.sqlite", max_discovery_rows_per_table=5) as store:
        now = _now()
        for i in range(20):
            store.record_ssdp_advertisement(
                interface="eth0", usn=f"uuid:fake-{i}", nt_or_st="upnp:rootdevice",
                server=None, location=None, max_age=3600, boot_id=None, config_id=None,
                seen_at=now + timedelta(seconds=i), source_ip=None, source_mac=None, family="ipv4",
            )
        counts = store.discovery_diagnostics()
        assert counts["ssdp_advertisements"] == 5


def test_device_store_rejects_non_positive_retention_caps_by_clamping(tmp_path: Path):
    # Defensive clamping, not a crash, for a caller passing a nonsensical cap.
    with DeviceStore(tmp_path / "db.sqlite", max_evidence_rows_per_mac=0) as store:
        store.record_address_evidence(
            "aa:bb:cc:dd:ee:ff", "10.0.0.1", interface="eth0", source="arp",
            kind="observed", seen_at=_now(),
        )
        assert len(store.address_evidence_for("aa:bb:cc:dd:ee:ff")) >= 1


# --- file/directory permissions (defense against a shared/multi-user host) --


def test_new_database_directory_is_owner_only(tmp_path: Path):
    import stat

    db_dir = tmp_path / "lanfence"
    store = DeviceStore(db_dir / "db.sqlite")
    store.close()
    assert stat.S_IMODE(db_dir.stat().st_mode) == 0o700


def test_new_database_file_is_owner_only(tmp_path: Path):
    import stat

    db_path = tmp_path / "lanfence" / "db.sqlite"
    store = DeviceStore(db_path)
    store.close()
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600


def test_ancestor_directories_are_not_forced_restrictive(tmp_path: Path):
    """Only the leaf (LAN-Fence-owned) directory is tightened - a shared
    ancestor like ~/.local/share must never be chmod'd by this."""

    import stat

    ancestor = tmp_path / "shared_ancestor"
    db_dir = ancestor / "lanfence"
    store = DeviceStore(db_dir / "db.sqlite")
    store.close()

    assert stat.S_IMODE(db_dir.stat().st_mode) == 0o700
    # The ancestor keeps whatever mkdir()/umask gave it - never forced to 0700.
    assert stat.S_IMODE(ancestor.stat().st_mode) != 0o700


def test_permissive_umask_does_not_leave_loose_permissions(tmp_path: Path):
    import os
    import stat

    old_umask = os.umask(0o000)
    try:
        db_dir = tmp_path / "lanfence"
        store = DeviceStore(db_dir / "db.sqlite")
        store.close()
    finally:
        os.umask(old_umask)

    assert stat.S_IMODE(db_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((db_dir / "db.sqlite").stat().st_mode) == 0o600


def test_existing_loosely_permissioned_directory_and_file_are_tightened(tmp_path: Path):
    import os
    import stat

    db_dir = tmp_path / "lanfence"
    db_dir.mkdir()
    os.chmod(db_dir, 0o755)
    db_path = db_dir / "db.sqlite"
    db_path.touch()
    os.chmod(db_path, 0o644)

    store = DeviceStore(db_path)
    store.close()

    assert stat.S_IMODE(db_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600


def test_existing_sqlite_sidecar_files_are_tightened(tmp_path: Path):
    """SQLite itself creates/removes -wal/-shm/-journal sidecars, outside
    this module's direct control (a stale rollback journal is even
    cleaned up by SQLite's own recovery on open) - so this exercises the
    permission-securing helper directly rather than relying on one still
    being present after a full DeviceStore open/close cycle."""

    import os
    import stat

    from lanfence.db import _secure_sqlite_sidecars

    db_dir = tmp_path / "lanfence"
    db_dir.mkdir()
    db_path = db_dir / "db.sqlite"
    db_path.touch()
    wal = db_dir / "db.sqlite-wal"
    wal.touch()
    os.chmod(wal, 0o644)

    _secure_sqlite_sidecars(db_path, expected_uid=os.getuid())

    assert stat.S_IMODE(wal.stat().st_mode) == 0o600


def test_refuses_a_directory_that_is_actually_a_symlink(tmp_path: Path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir = tmp_path / "lanfence"
    link_dir.symlink_to(real_dir)

    try:
        DeviceStore(link_dir / "db.sqlite")
        assert False, "expected a RuntimeError"
    except RuntimeError as exc:
        assert "symlink" in str(exc)


def test_refuses_a_directory_owned_by_an_unexpected_uid(tmp_path: Path, monkeypatch):
    db_dir = tmp_path / "lanfence"
    db_dir.mkdir()
    monkeypatch.setattr("lanfence.db._expected_owner_uid", lambda: 999999)

    try:
        DeviceStore(db_dir / "db.sqlite")
        assert False, "expected a PermissionError"
    except PermissionError as exc:
        assert "owned by uid" in str(exc)


def test_refuses_a_database_file_owned_by_an_unexpected_uid(tmp_path: Path, monkeypatch):
    db_dir = tmp_path / "lanfence"
    db_dir.mkdir()
    db_path = db_dir / "db.sqlite"
    db_path.touch()
    monkeypatch.setattr("lanfence.db._expected_owner_uid", lambda: 999999)

    try:
        DeviceStore(db_path)
        assert False, "expected a PermissionError"
    except PermissionError as exc:
        assert "owned by uid" in str(exc)


def test_expected_owner_uid_is_current_user_when_not_root(monkeypatch):
    import os

    from lanfence.db import _expected_owner_uid

    monkeypatch.setattr("lanfence.db.os.geteuid", lambda: 1000)
    assert _expected_owner_uid() == os.getuid()


def test_expected_owner_uid_prefers_sudo_user_when_run_as_root(monkeypatch):
    from lanfence.db import _expected_owner_uid

    monkeypatch.setattr("lanfence.db.os.geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr("pwd.getpwnam", lambda name: type("_pw", (), {"pw_uid": 1234})())
    assert _expected_owner_uid() == 1234


def test_expected_owner_uid_root_without_sudo_user_stays_root(monkeypatch):
    from lanfence.db import _expected_owner_uid

    monkeypatch.setattr("lanfence.db.os.geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert _expected_owner_uid() == 0


def test_a_second_devicestore_open_on_an_already_secured_database_is_a_noop(tmp_path: Path):
    """Reopening an already-correctly-permissioned database (the normal
    case for every command after the first) must not raise or need to
    change anything."""

    import stat

    db_path = tmp_path / "lanfence" / "db.sqlite"
    DeviceStore(db_path).close()
    store2 = DeviceStore(db_path)
    store2.close()
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600


# --- symlink attack resistance ----------------------------------------


def test_refuses_dangling_symlink_at_the_database_path(tmp_path: Path):
    """A pre-planted dangling symlink must never be "completed" (its
    target created) by opening the database - the target must not exist
    afterwards."""

    db_dir = tmp_path / "lanfence"
    db_dir.mkdir()
    outside_target = tmp_path / "outside_target.sqlite"
    link = db_dir / "db.sqlite"
    link.symlink_to(outside_target)

    try:
        DeviceStore(link)
        assert False, "expected a RuntimeError"
    except RuntimeError as exc:
        assert "symlink" in str(exc)
    assert not outside_target.exists()


def test_refuses_symlink_to_an_existing_file_and_leaves_it_untouched(tmp_path: Path):
    db_dir = tmp_path / "lanfence"
    db_dir.mkdir()
    victim = tmp_path / "victim_file"
    original = "original contents - must not be touched"
    victim.write_text(original)
    link = db_dir / "db.sqlite"
    link.symlink_to(victim)

    try:
        DeviceStore(link)
        assert False, "expected a RuntimeError"
    except RuntimeError as exc:
        assert "symlink" in str(exc)
    assert victim.read_text() == original


def test_refuses_symlinked_state_directory(tmp_path: Path):
    """A symlinked leaf directory (not just the db file itself) must be
    refused - this is 'an unsafe parent' relative to the db file."""

    real = tmp_path / "real"
    real.mkdir()
    link_dir = tmp_path / "lanfence"
    link_dir.symlink_to(real)

    try:
        DeviceStore(link_dir / "db.sqlite")
        assert False, "expected a RuntimeError"
    except RuntimeError as exc:
        assert "symlink" in str(exc) or "directory" in str(exc)


def test_refuses_symlinked_sqlite_sidecar_and_leaves_target_untouched(tmp_path: Path):
    db_dir = tmp_path / "lanfence"
    db_dir.mkdir()
    db_path = db_dir / "db.sqlite"
    db_path.touch()
    victim = tmp_path / "victim_wal"
    victim.write_text("do not touch")
    (db_dir / "db.sqlite-wal").symlink_to(victim)

    try:
        DeviceStore(db_path)
        assert False, "expected a RuntimeError"
    except RuntimeError as exc:
        assert "symlink" in str(exc)
    assert victim.read_text() == "do not touch"


def test_normal_creation_still_works_after_symlink_hardening(tmp_path: Path):
    """The common, non-adversarial case (nothing exists yet) must be
    completely unaffected by the symlink-refusing open."""

    db_path = tmp_path / "lanfence" / "db.sqlite"
    store = DeviceStore(db_path)
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now())
    store.close()
    assert db_path.exists()

    # Reopening an already-real, already-secured file also still works.
    store2 = DeviceStore(db_path)
    assert store2.get_device("aa:bb:cc:dd:ee:ff") is not None
    store2.close()


def test_ancestor_symlink_is_not_disturbed(tmp_path: Path):
    """Only the final leaf directory/file are ever checked for symlinks -
    a legitimate symlinked *ancestor* (a platform alias, an intentional
    bind-mount-style setup) is left completely alone."""

    real_ancestor = tmp_path / "real_ancestor"
    real_ancestor.mkdir()
    aliased_ancestor = tmp_path / "aliased_ancestor"
    aliased_ancestor.symlink_to(real_ancestor)

    db_path = aliased_ancestor / "lanfence" / "db.sqlite"
    store = DeviceStore(db_path)
    store.close()

    assert db_path.exists()
    assert aliased_ancestor.is_symlink()  # untouched - never converted or rejected


def test_open_or_create_database_file_atomic_create_excludes_existing_symlink(tmp_path: Path):
    """Direct unit check that the O_CREAT|O_EXCL path never silently
    "wins" a race against something already there, symlink included."""

    from lanfence.db import _open_or_create_database_file

    target = tmp_path / "target"
    link = tmp_path / "db.sqlite"
    link.symlink_to(target)

    try:
        _open_or_create_database_file(link, expected_uid=os.getuid())
        assert False, "expected a RuntimeError"
    except RuntimeError:
        pass
    assert not target.exists()


def test_open_nofollow_existing_raises_filenotfounderror_for_missing_path(tmp_path: Path):
    from lanfence.db import _open_nofollow_existing

    missing = tmp_path / "does-not-exist"
    try:
        _open_nofollow_existing(missing, os.O_RDWR)
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass
