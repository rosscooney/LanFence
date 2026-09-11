from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from lanfence import scanner
from lanfence.allowlist import Allowlist
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.engine import (
    build_findings,
    build_inventory,
    filter_rate_limited,
    filter_snoozed,
    is_review_needed,
    process_sighting,
    run_active_sweep,
)
from lanfence.fingerprint import SignatureSet
from lanfence.models import Device, Finding


def _now():
    return datetime.now(timezone.utc)


def _device(**overrides):
    base = dict(
        mac="aa:bb:cc:dd:ee:ff", ip="1.2.3.4", hostname=None, vendor=None,
        status="online", first_seen=_now(), last_seen=_now(),
        allowlisted=False, allowlist_name=None, fingerprints=[],
    )
    base.update(overrides)
    return Device(**base)


def test_build_findings_none_for_routine_refresh():
    assert build_findings(_device(), None, []) == []


def test_build_findings_none_for_disconnect():
    assert build_findings(_device(), "disconnected", []) == []


def test_build_findings_new_unknown_device_defaults_medium():
    findings = build_findings(_device(), "new_device", [])
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].mac == "aa:bb:cc:dd:ee:ff"


def test_build_findings_new_allowlisted_device_is_info():
    device = _device(allowlisted=True, allowlist_name="My Laptop")
    findings = build_findings(device, "new_device", [])
    assert findings[0].severity == "info"
    assert "My Laptop" in findings[0].title


def test_build_findings_new_device_severity_follows_top_signature():
    from lanfence.fingerprint import SignatureMatch

    matches = [
        SignatureMatch(category="pwnagotchi", severity="high", title="t", description="d", evidence="e"),
    ]
    findings = build_findings(_device(), "new_device", matches)
    assert findings[0].severity == "high"


def test_build_findings_reappeared_non_allowlisted_is_info_unless_high_signature():
    findings = build_findings(_device(), "reappeared", [])
    assert findings[0].severity == "info"

    from lanfence.fingerprint import SignatureMatch

    high_match = [SignatureMatch(category="x", severity="high", title="t", description="d", evidence="e")]
    findings = build_findings(_device(), "reappeared", high_match)
    assert findings[0].severity == "high"


def test_build_findings_reappeared_allowlisted_is_info():
    device = _device(allowlisted=True, allowlist_name="NAS")
    findings = build_findings(device, "reappeared", [])
    assert findings[0].severity == "info"
    assert "NAS" in findings[0].title


def test_process_sighting_new_device_and_allowlist_downgrade(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.engine.scanner.resolve_hostname", lambda ip, timeout=1.0: None)
    cfg = Config()
    store = DeviceStore(tmp_path / "db.sqlite")
    allowlist = Allowlist.load(None)
    allowlist.add("aa:bb:cc:dd:ee:ff", "Trusted Thing")
    signatures = SignatureSet.load()

    device, event_type, findings = process_sighting(
        mac="AA:BB:CC:DD:EE:FF", ip="10.0.0.5", seen_at=_now(),
        store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
    )
    assert event_type == "new_device"
    assert device.allowlisted is True
    assert device.allowlist_name == "Trusted Thing"
    assert findings[0].severity == "info"
    store.close()


def test_process_sighting_second_call_is_routine(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.engine.scanner.resolve_hostname", lambda ip, timeout=1.0: None)
    cfg = Config()
    store = DeviceStore(tmp_path / "db.sqlite")
    allowlist = Allowlist.load(None)
    signatures = SignatureSet.load()

    process_sighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now(),
                      store=store, allowlist=allowlist, signatures=signatures, cfg=cfg)
    _, event_type, findings = process_sighting(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now(),
        store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
    )
    assert event_type is None
    assert findings == []
    store.close()


def test_process_sighting_hostname_hint_skips_reverse_dns(tmp_path: Path):
    with patch("lanfence.engine.scanner.resolve_hostname") as resolve_mock:
        store = DeviceStore(tmp_path / "db.sqlite")
        device, _, _ = process_sighting(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now(),
            store=store, allowlist=Allowlist.load(None), signatures=SignatureSet.load(),
            cfg=Config(), hostname_hint="Georges-iPhone",
        )
        store.close()
    resolve_mock.assert_not_called()
    assert device.hostname == "Georges-iPhone"


def test_process_sighting_no_hint_falls_back_to_reverse_dns(tmp_path: Path):
    with patch("lanfence.engine.scanner.resolve_hostname", return_value="dns-name.local") as resolve_mock:
        store = DeviceStore(tmp_path / "db.sqlite")
        device, _, _ = process_sighting(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now(),
            store=store, allowlist=Allowlist.load(None), signatures=SignatureSet.load(),
            cfg=Config(),
        )
        store.close()
    resolve_mock.assert_called_once()
    assert device.hostname == "dns-name.local"


def test_run_active_sweep_merges_ipv4_and_ipv6_sightings(tmp_path: Path):
    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    v6 = scanner.ArpSighting(mac="11:22:33:44:55:66", ip="fe80::1", seen_at=_now())

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]), \
         patch.object(scanner, "active_scan_v6", return_value=[v6]):
        store = DeviceStore(tmp_path / "db.sqlite")
        result = run_active_sweep(
            Config(), store, Allowlist.load(None), SignatureSet.load(),
            interface="eth0", subnet="192.168.1.0/24",
        )
        store.close()

    macs_seen = {d.mac: d.ip for d in result.devices}
    assert macs_seen == {"aa:bb:cc:dd:ee:ff": "192.168.1.5", "11:22:33:44:55:66": "fe80::1"}
    assert {e.mac for e in result.events} == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
    assert result.errors == []


def test_run_active_sweep_skips_ipv6_when_disabled(tmp_path: Path):
    cfg = Config()
    cfg.scan.ipv6 = False

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]) as v4_mock, \
         patch.object(scanner, "active_scan_v6") as v6_mock:
        store = DeviceStore(tmp_path / "db.sqlite")
        run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.close()

    v4_mock.assert_called_once()
    v6_mock.assert_not_called()


def test_run_active_sweep_total_failure_does_not_mark_devices_offline(tmp_path: Path):
    """Regression test: if every scan mechanism fails (e.g. no root this
    round), there is no information to act on - previously-online devices
    must not be marked disconnected just because nothing could be checked."""

    db_path = tmp_path / "db.sqlite"
    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]), \
         patch.object(scanner, "active_scan_v6", return_value=[]):
        store = DeviceStore(db_path)
        run_active_sweep(Config(), store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.close()

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", side_effect=scanner.ScannerUnavailable("no root")), \
         patch.object(scanner, "active_scan_v6", side_effect=scanner.ScannerUnavailable("no root v6")):
        store = DeviceStore(db_path)
        result = run_active_sweep(Config(), store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        still_online = store.get_device("aa:bb:cc:dd:ee:ff").status
        store.close()

    assert still_online == "online"
    assert result.events == []
    assert len(result.errors) == 2


def test_run_active_sweep_partial_success_still_marks_offline(tmp_path: Path):
    """When at least one mechanism succeeds, a device not seen by it is a
    real disconnect, even if the other mechanism failed."""

    db_path = tmp_path / "db.sqlite"
    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]), \
         patch.object(scanner, "active_scan_v6", return_value=[]):
        store = DeviceStore(db_path)
        run_active_sweep(Config(), store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.close()

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", side_effect=scanner.ScannerUnavailable("no root v6")):
        store = DeviceStore(db_path)
        result = run_active_sweep(Config(), store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        still_online = store.get_device("aa:bb:cc:dd:ee:ff").status
        store.close()

    assert still_online == "offline"
    assert any(e.event_type == "disconnected" for e in result.events)


# --- filter_rate_limited ------------------------------------------------


def _cfg_with_rate_limit(seconds: float) -> Config:
    cfg = Config()
    cfg.alerts.rate_limit_seconds = seconds
    return cfg


def test_filter_rate_limited_keeps_first_alert_for_a_device(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    finding = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="medium")
    kept = filter_rate_limited([finding], store, _cfg_with_rate_limit(900).alerts, now=_now())
    store.close()
    assert kept == [finding]


def test_filter_rate_limited_suppresses_repeat_within_cooldown(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_rate_limit(900)
    t0 = _now()
    first = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="medium")
    second = Finding(mac="aa:bb:cc:dd:ee:ff", title="t again", severity="medium")

    kept_first = filter_rate_limited([first], store, cfg.alerts, now=t0)
    kept_second = filter_rate_limited([second], store, cfg.alerts, now=t0)
    store.close()

    assert kept_first == [first]
    assert kept_second == []


def test_filter_rate_limited_keeps_escalation_within_cooldown(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_rate_limit(900)
    t0 = _now()
    low = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="info")
    high = Finding(mac="aa:bb:cc:dd:ee:ff", title="t escalated", severity="high")

    filter_rate_limited([low], store, cfg.alerts, now=t0)
    kept = filter_rate_limited([high], store, cfg.alerts, now=t0)
    store.close()

    assert kept == [high]


def test_filter_rate_limited_zero_disables_rate_limiting(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_rate_limit(0)
    t0 = _now()
    finding = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="medium")

    kept_first = filter_rate_limited([finding], store, cfg.alerts, now=t0)
    kept_second = filter_rate_limited([finding], store, cfg.alerts, now=t0)
    store.close()

    assert kept_first == [finding]
    assert kept_second == [finding]


def test_filter_rate_limited_processes_highest_severity_first_in_one_batch(tmp_path: Path):
    """A batch containing both a low- and a high-severity finding for the
    same MAC (e.g. one finding per matched signature) must not let the low
    one "claim" the alert slot and suppress the high one processed after it."""

    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_rate_limit(900)
    low = Finding(mac="aa:bb:cc:dd:ee:ff", title="low", severity="info")
    high = Finding(mac="aa:bb:cc:dd:ee:ff", title="high", severity="high")

    kept = filter_rate_limited([low, high], store, cfg.alerts, now=_now())
    store.close()

    assert kept == [high]


def test_filter_rate_limited_independent_per_mac(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_rate_limit(900)
    t0 = _now()
    a = Finding(mac="aa:bb:cc:dd:ee:ff", title="a", severity="medium")
    b = Finding(mac="11:22:33:44:55:66", title="b", severity="medium")

    filter_rate_limited([a], store, cfg.alerts, now=t0)
    kept = filter_rate_limited([b], store, cfg.alerts, now=t0)
    store.close()

    assert kept == [b]


# --- filter_snoozed ------------------------------------------------------


def test_filter_snoozed_removes_findings_for_a_snoozed_mac(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    now = _now()
    store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now + timedelta(hours=1), updated_at=now)
    finding = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="high")

    kept = filter_snoozed([finding], store, now=now)
    store.close()
    assert kept == []


def test_filter_snoozed_keeps_findings_for_unsnoozed_or_expired_mac(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    now = _now()
    store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now - timedelta(hours=1), updated_at=now)  # expired
    not_snoozed = Finding(mac="11:22:33:44:55:66", title="t", severity="high")
    expired_snooze = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="high")

    kept = filter_snoozed([not_snoozed, expired_snooze], store, now=now)
    store.close()
    assert kept == [not_snoozed, expired_snooze]


def test_filter_snoozed_does_not_consume_alert_cooldown(tmp_path: Path):
    """Regression test for the spec requirement: snooze filtering must run
    before cooldown bookkeeping, so a suppressed finding never marks the
    cooldown as used - due_for_alert must still return True afterward."""

    store = DeviceStore(tmp_path / "db.sqlite")
    now = _now()
    store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now + timedelta(hours=1), updated_at=now)
    finding = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="high")

    kept = filter_snoozed([finding], store, now=now)
    assert kept == []
    # the cooldown was never touched by the (correctly) suppressed finding
    assert store.due_for_alert("aa:bb:cc:dd:ee:ff", "high", now=now, cooldown_seconds=900) is True
    store.close()


# --- build_inventory / is_review_needed -------------------------------------


def test_build_inventory_joins_allowlist_and_review_state(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    now = _now()
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None, seen_at=now)
    store.observe(mac="11:22:33:44:55:66", ip="2.2.2.2", hostname=None, vendor=None, seen_at=now)
    store.set_investigating("11:22:33:44:55:66", notes="hmm", updated_at=now)

    allowlist = Allowlist.load(None)
    allowlist.add("aa:bb:cc:dd:ee:ff", "Trusted Thing")

    inventory = build_inventory(store, allowlist)
    store.close()
    by_mac = {d.mac: d for d in inventory}

    assert by_mac["aa:bb:cc:dd:ee:ff"].allowlisted is True
    assert by_mac["aa:bb:cc:dd:ee:ff"].allowlist_name == "Trusted Thing"
    assert by_mac["11:22:33:44:55:66"].review_state == "investigating"
    assert by_mac["11:22:33:44:55:66"].review_notes == "hmm"


def test_is_review_needed_true_for_plain_untrusted_device():
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now())
    assert is_review_needed(device, now=_now()) is True


def test_is_review_needed_false_when_allowlisted():
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), allowlisted=True)
    assert is_review_needed(device, now=_now()) is False


def test_is_review_needed_false_when_investigating():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), review_state="investigating"
    )
    assert is_review_needed(device, now=_now()) is False


def test_is_review_needed_false_when_actively_snoozed():
    now = _now()
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now,
        review_state="snoozed", snoozed_until=now + timedelta(hours=1),
    )
    assert is_review_needed(device, now=now) is False


def test_is_review_needed_true_when_snooze_expired():
    now = _now()
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now,
        review_state="snoozed", snoozed_until=now - timedelta(hours=1),
    )
    assert is_review_needed(device, now=now) is True
