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
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip=None, hostname=None, vendor=None, seen_at=t0)
        store.observe(mac="11:22:33:44:55:66", ip=None, hostname=None, vendor=None, seen_at=t0)
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
