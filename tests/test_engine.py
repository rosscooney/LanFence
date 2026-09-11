from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from lanfence import scanner
from lanfence.allowlist import Allowlist
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.engine import build_findings, process_sighting, run_active_sweep
from lanfence.fingerprint import SignatureSet
from lanfence.models import Device


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
