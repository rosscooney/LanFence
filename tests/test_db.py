from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from lanfence.db import DeviceStore


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
