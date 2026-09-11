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
