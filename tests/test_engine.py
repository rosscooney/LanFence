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
    apply_self_trust,
    build_findings,
    build_inventory,
    coalesce_sightings,
    enrich_missing_hostnames,
    evaluate_availability,
    filter_rate_limited,
    filter_snoozed,
    is_review_needed,
    process_sighting,
    resolve_scan_interfaces,
    run_active_sweep,
    run_active_sweep_multi,
)
from lanfence.fingerprint import SignatureSet
from lanfence.models import Device, DeviceMetadata, Finding


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


def test_build_findings_new_device_evidence_includes_metadata_when_set():
    metadata = DeviceMetadata(mac="aa:bb:cc:dd:ee:ff", owner="Emily", location="Home office")
    device = _device(hostname="Galaxy-A33-5G", vendor="Samsung", metadata=metadata)
    findings = build_findings(device, "new_device", [])
    evidence = findings[0].evidence
    assert "Hostname: Galaxy-A33-5G" in evidence
    assert "Vendor: Samsung" in evidence
    assert "Owner: Emily" in evidence
    assert "Location: Home office" in evidence


def test_build_findings_new_device_evidence_omits_metadata_when_unset():
    findings = build_findings(_device(), "new_device", [])
    evidence = findings[0].evidence
    assert not any(e.startswith(("Owner:", "Purpose:", "Group:", "Location:")) for e in evidence)


def test_build_findings_allowlisted_device_evidence_includes_name_first():
    device = _device(allowlisted=True, allowlist_name="Emily Work Phone")
    findings = build_findings(device, "new_device", [])
    evidence = findings[0].evidence
    assert evidence[0] == "Name: Emily Work Phone"


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


# --- finding "kind" tagging / intermittent-presence suppression -------------


def test_new_device_finding_is_always_security_kind():
    findings = build_findings(_device(), "new_device", [])
    assert findings[0].kind == "security"

    allowlisted = _device(allowlisted=True, allowlist_name="X")
    findings = build_findings(allowlisted, "new_device", [])
    assert findings[0].kind == "security"


def test_routine_reappear_is_lifecycle_kind():
    findings = build_findings(_device(), "reappeared", [])
    assert len(findings) == 1
    assert findings[0].kind == "lifecycle"


def test_allowlisted_reappear_is_lifecycle_kind():
    device = _device(allowlisted=True, allowlist_name="NAS")
    findings = build_findings(device, "reappeared", [])
    assert len(findings) == 1
    assert findings[0].kind == "lifecycle"


def test_reappear_with_high_signature_splits_into_security_and_lifecycle():
    from lanfence.fingerprint import SignatureMatch

    high_match = [SignatureMatch(category="x", severity="high", title="t", description="d", evidence="e")]
    findings = build_findings(_device(), "reappeared", high_match)

    assert len(findings) == 2
    kinds = {f.kind for f in findings}
    assert kinds == {"security", "lifecycle"}
    security = next(f for f in findings if f.kind == "security")
    lifecycle = next(f for f in findings if f.kind == "lifecycle")
    assert security.severity == "high"
    assert lifecycle.severity == "info"


def test_intermittent_policy_suppresses_lifecycle_but_keeps_security():
    device = _device(presence_policy="intermittent")
    assert build_findings(device, "reappeared", []) == []  # routine-only: fully suppressed

    from lanfence.fingerprint import SignatureMatch

    high_match = [SignatureMatch(category="x", severity="high", title="t", description="d", evidence="e")]
    findings = build_findings(device, "reappeared", high_match)
    assert len(findings) == 1
    assert findings[0].kind == "security"
    assert findings[0].severity == "high"


def test_intermittent_policy_never_suppresses_first_discovery():
    device = _device(presence_policy="intermittent")
    findings = build_findings(device, "new_device", [])
    assert len(findings) == 1
    assert findings[0].kind == "security"


def test_intermittent_policy_does_not_affect_allowlisted_reappear_visibility():
    """An allowlisted device's reappearance is already info/lifecycle either
    way - intermittent just means it, too, is suppressed (it was always a
    pure lifecycle announcement with no independent security content)."""

    device = _device(allowlisted=True, allowlist_name="NAS", presence_policy="intermittent")
    assert build_findings(device, "reappeared", []) == []


def test_unspecified_policy_preserves_existing_behavior():
    device = _device(presence_policy="unspecified")
    assert len(build_findings(device, "reappeared", [])) == 1
    assert len(build_findings(device, "new_device", [])) == 1


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


def test_process_sighting_new_device_finding_includes_operator_metadata(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.engine.scanner.resolve_hostname", lambda ip, timeout=1.0: None)
    cfg = Config()
    store = DeviceStore(tmp_path / "db.sqlite")
    store.update_device_metadata(
        "aa:bb:cc:dd:ee:ff", owner="Emily", location="Home office", updated_at=_now(),
    )
    allowlist = Allowlist.load(None)
    signatures = SignatureSet.load()

    device, event_type, findings = process_sighting(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now(),
        store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
    )
    assert event_type == "new_device"
    assert "Owner: Emily" in findings[0].evidence
    assert "Location: Home office" in findings[0].evidence
    store.close()


def test_process_sighting_routine_refresh_skips_metadata_lookup(tmp_path: Path, monkeypatch):
    """No finding can result from a routine still-online refresh
    (event_type=None) - the metadata query is skipped entirely rather
    than fetched and discarded."""

    monkeypatch.setattr("lanfence.engine.scanner.resolve_hostname", lambda ip, timeout=1.0: None)
    cfg = Config()
    store = DeviceStore(tmp_path / "db.sqlite")
    allowlist = Allowlist.load(None)
    signatures = SignatureSet.load()
    t0 = _now()
    process_sighting(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0,
        store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
    )

    with patch.object(store, "get_device_metadata") as metadata_mock:
        device, event_type, findings = process_sighting(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0 + timedelta(seconds=1),
            store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
        )
    assert event_type is None
    assert findings == []
    metadata_mock.assert_not_called()
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


def test_process_sighting_observes_a_live_presence_policy_change(tmp_path: Path, monkeypatch):
    """A long-lived monitor process shares one DeviceStore handle across
    every sweep - presence is read fresh from the database on every call,
    so a policy edit from another terminal takes effect on the very next
    sighting, without restarting the monitor."""

    monkeypatch.setattr("lanfence.engine.scanner.resolve_hostname", lambda ip, timeout=1.0: None)
    cfg = Config()
    store = DeviceStore(tmp_path / "db.sqlite")
    allowlist = Allowlist.load(None)
    signatures = SignatureSet.load()
    t0 = _now()

    # First sighting, then goes offline and reappears - default (unspecified)
    # policy shows the routine lifecycle finding.
    process_sighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0,
                      store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
                      interface="eth0", subnet="10.0.0.0/24")
    store.mark_offline(set(), as_of=t0 + timedelta(seconds=1), grace_seconds=0, missed_after=1,
                        ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0")
    _, _, findings_before = process_sighting(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0 + timedelta(seconds=2),
        store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
        interface="eth0", subnet="10.0.0.0/24",
    )
    assert any(f.kind == "lifecycle" for f in findings_before)

    # Policy edit "from another terminal" - same store, no restart.
    store.set_presence_policy("aa:bb:cc:dd:ee:ff", "intermittent", updated_at=t0 + timedelta(seconds=3))

    store.mark_offline(set(), as_of=t0 + timedelta(seconds=4), grace_seconds=0, missed_after=1,
                        ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0")
    device_after, _, findings_after = process_sighting(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0 + timedelta(seconds=5),
        store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
        interface="eth0", subnet="10.0.0.0/24",
    )
    store.close()

    assert device_after.presence_policy == "intermittent"
    assert findings_after == []  # routine reappearance now suppressed


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


# --- always-on availability: absence/recovery via process_sighting ---------


def test_process_sighting_reappear_emits_recovery_after_alerted_absence(tmp_path: Path):
    monkeypatch_target = "lanfence.engine.scanner.resolve_hostname"
    with patch(monkeypatch_target, return_value=None):
        store = DeviceStore(tmp_path / "db.sqlite")
        allowlist = Allowlist.load(None)
        signatures = SignatureSet.load()
        cfg = Config()
        t0 = _now()

        process_sighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0,
                          store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
                          interface="eth0", subnet="10.0.0.0/24")
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=t0)
        store.mark_offline(set(), as_of=t0, grace_seconds=0, missed_after=1,
                            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0")
        store.evaluate_availability(
            as_of=t0 + timedelta(seconds=600), default_offline_after_seconds=300,
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0",
        )
        assert store.get_presence("aa:bb:cc:dd:ee:ff").availability_alerted is True

        device, event_type, findings = process_sighting(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0 + timedelta(seconds=700),
            store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
            interface="eth0", subnet="10.0.0.0/24",
        )
        store.close()

    assert event_type == "reappeared"
    recovery = [f for f in findings if f.kind == "availability"]
    assert len(recovery) == 1
    assert recovery[0].severity == "info"


def test_process_sighting_reappear_without_prior_alert_has_no_recovery_finding(tmp_path: Path):
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None):
        store = DeviceStore(tmp_path / "db.sqlite")
        allowlist = Allowlist.load(None)
        signatures = SignatureSet.load()
        cfg = Config()
        t0 = _now()

        process_sighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0,
                          store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
                          interface="eth0", subnet="10.0.0.0/24")
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=t0)
        store.mark_offline(set(), as_of=t0, grace_seconds=0, missed_after=1,
                            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0")
        # Reappears quickly - never reached the absence threshold, never alerted.

        _, event_type, findings = process_sighting(
            mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0 + timedelta(seconds=5),
            store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
            interface="eth0", subnet="10.0.0.0/24",
        )
        store.close()

    assert event_type == "reappeared"
    assert [f for f in findings if f.kind == "availability"] == []


def test_trusted_always_on_device_still_gets_availability_finding(tmp_path: Path):
    """Trust must not downgrade or suppress an explicitly requested
    availability finding."""

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None):
        store = DeviceStore(tmp_path / "db.sqlite")
        allowlist = Allowlist.load(None)
        allowlist.add("aa:bb:cc:dd:ee:ff", "Trusted Server")
        signatures = SignatureSet.load()
        cfg = Config()
        t0 = _now()

        process_sighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=t0,
                          store=store, allowlist=allowlist, signatures=signatures, cfg=cfg,
                          interface="eth0", subnet="10.0.0.0/24")
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=t0)
        store.mark_offline(set(), as_of=t0, grace_seconds=0, missed_after=1,
                            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0")

        due = evaluate_availability(
            store, cfg, as_of=t0 + timedelta(seconds=600),
            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", ipv6_covered=False, interface="eth0",
        )
        store.close()

    assert len(due) == 1
    assert due[0].severity == "medium"
    assert due[0].kind == "availability"


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


def test_run_active_sweep_includes_configured_site_name_and_location(tmp_path: Path):
    cfg = Config(site={"name": "My Home LAN", "location": "Living room"})
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", return_value=[]):
        store = DeviceStore(tmp_path / "db.sqlite")
        result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(), interface="eth0", subnet="192.168.1.0/24")
        store.close()
    assert result.site_name == "My Home LAN"
    assert result.site_location == "Living room"


def test_run_active_sweep_site_defaults_to_none(tmp_path: Path):
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", return_value=[]):
        store = DeviceStore(tmp_path / "db.sqlite")
        result = run_active_sweep(Config(), store, Allowlist.load(None), SignatureSet.load(), interface="eth0", subnet="192.168.1.0/24")
        store.close()
    assert result.site_name is None
    assert result.site_location is None


def test_run_active_sweep_same_mac_dual_stack_retains_both_addresses_one_event(tmp_path: Path):
    """The core address/name-provenance requirement: multiple addresses for
    one MAC in the same sweep must all reach evidence storage, without
    creating duplicate new_device/reappeared events or findings."""

    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now(), source="arp")
    v6 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="fe80::1", seen_at=_now(), source="ipv6_nd")

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]), \
         patch.object(scanner, "active_scan_v6", return_value=[v6]):
        store = DeviceStore(tmp_path / "db.sqlite")
        result = run_active_sweep(
            Config(), store, Allowlist.load(None), SignatureSet.load(),
            interface="eth0", subnet="192.168.1.0/24",
        )
        evidence = store.address_evidence_for("aa:bb:cc:dd:ee:ff")
        store.close()

    assert {e.ip for e in evidence} == {"192.168.1.5", "fe80::1"}
    assert len(result.events) == 1  # exactly one new_device event, not two
    assert result.events[0].event_type == "new_device"
    assert len(result.findings) == 1  # exactly one finding, not two


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


def _cfg_immediate_offline() -> Config:
    """Compatibility settings that restore pre-grace-period behavior:
    disconnect on the very first eligible missed sweep."""

    cfg = Config()
    cfg.scan.offline_grace_seconds = 0
    cfg.scan.offline_after_missed_scans = 1
    cfg.scan.offline_retry_probe = False  # not under test here - see test_offline_retry_* below
    return cfg


def test_run_active_sweep_partial_success_still_marks_offline(tmp_path: Path):
    """When at least one mechanism succeeds, a device not seen by it is a
    real disconnect, even if the other mechanism failed."""

    db_path = tmp_path / "db.sqlite"
    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]), \
         patch.object(scanner, "active_scan_v6", return_value=[]):
        store = DeviceStore(db_path)
        run_active_sweep(_cfg_immediate_offline(), store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.close()

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", side_effect=scanner.ScannerUnavailable("no root v6")):
        store = DeviceStore(db_path)
        result = run_active_sweep(_cfg_immediate_offline(), store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        still_online = store.get_device("aa:bb:cc:dd:ee:ff").status
        store.close()

    assert still_online == "offline"
    assert any(e.event_type == "disconnected" for e in result.events)


# --- multiple interfaces -------------------------------------------------

_SUBNETS = {"eth0": "192.168.1.0/24", "eth0.10": "192.168.10.0/24"}


def _per_interface_scan(by_interface):
    def fake_active_scan(*, subnet, interface, timeout):
        return by_interface.get(interface, [])
    return fake_active_scan


def test_resolve_scan_interfaces_cli_override_wins():
    cfg = Config(scan={"interfaces": ["eth0", "eth0.10"], "interface": "wlan0"})
    assert resolve_scan_interfaces(cfg, "eth1") == ["eth1"]


def test_resolve_scan_interfaces_prefers_configured_list_over_legacy_single():
    cfg = Config(scan={"interfaces": ["eth0", "eth0.10"], "interface": "wlan0"})
    assert resolve_scan_interfaces(cfg, None) == ["eth0", "eth0.10"]


def test_resolve_scan_interfaces_falls_back_to_legacy_single_then_auto():
    assert resolve_scan_interfaces(Config(scan={"interface": "wlan0"}), None) == ["wlan0"]
    with patch.object(scanner, "default_interface", return_value="eth9"):
        assert resolve_scan_interfaces(Config(), None) == ["eth9"]
    with patch.object(scanner, "default_interface", return_value=None):
        assert resolve_scan_interfaces(Config(), None) == []


def test_run_active_sweep_multi_merges_every_interface(tmp_path: Path):
    a = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    b = scanner.ArpSighting(mac="11:22:33:44:55:66", ip="192.168.10.7", seen_at=_now())

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "local_subnet", side_effect=_SUBNETS.get), \
         patch.object(scanner, "active_scan", side_effect=_per_interface_scan({"eth0": [a], "eth0.10": [b]})), \
         patch.object(scanner, "active_scan_v6", return_value=[]):
        store = DeviceStore(tmp_path / "db.sqlite")
        result = run_active_sweep_multi(
            Config(), store, Allowlist.load(None), SignatureSet.load(), interfaces=["eth0", "eth0.10"],
        )
        store.close()

    assert result.interfaces == ["eth0", "eth0.10"]
    assert result.interface is None
    assert {d.mac for d in result.devices} == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
    assert {e.mac for e in result.events if e.event_type == "new_device"} == {
        "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
    }


def test_run_active_sweep_multi_prefixes_errors_with_their_interface(tmp_path: Path):
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "local_subnet", side_effect=_SUBNETS.get), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", side_effect=scanner.ScannerUnavailable("no v6")):
        store = DeviceStore(tmp_path / "db.sqlite")
        result = run_active_sweep_multi(
            Config(), store, Allowlist.load(None), SignatureSet.load(), interfaces=["eth0", "eth0.10"],
        )
        store.close()

    assert any(e.startswith("eth0: ") for e in result.errors)
    assert any(e.startswith("eth0.10: ") for e in result.errors)


def test_run_active_sweep_multi_ignores_configured_subnet(tmp_path: Path):
    seen_subnets = {}

    def fake_active_scan(*, subnet, interface, timeout):
        seen_subnets[interface] = subnet
        return []

    cfg = Config(scan={"subnet": "172.16.0.0/16"})
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "local_subnet", side_effect=_SUBNETS.get), \
         patch.object(scanner, "active_scan", side_effect=fake_active_scan), \
         patch.object(scanner, "active_scan_v6", return_value=[]):
        store = DeviceStore(tmp_path / "db.sqlite")
        run_active_sweep_multi(cfg, store, Allowlist.load(None), SignatureSet.load(), interfaces=["eth0", "eth0.10"])
        store.close()

    assert seen_subnets == _SUBNETS
    assert cfg.scan.subnet == "172.16.0.0/16"  # the caller's config is left untouched


def test_run_active_sweep_multi_never_marks_a_device_offline_from_another_interfaces_sweep(tmp_path: Path):
    """A device on eth0 that eth0's sweep just saw must not count as a miss
    during eth0.10's sweep in the same round - offline detection is scoped
    to the interface each device was last seen on."""

    a = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    b = scanner.ArpSighting(mac="11:22:33:44:55:66", ip="192.168.10.7", seen_at=_now())
    scans = _per_interface_scan({"eth0": [a], "eth0.10": [b]})

    db_path = tmp_path / "db.sqlite"
    for _round in range(3):
        with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
             patch.object(scanner, "local_subnet", side_effect=_SUBNETS.get), \
             patch.object(scanner, "active_scan", side_effect=scans), \
             patch.object(scanner, "active_scan_v6", return_value=[]):
            store = DeviceStore(db_path)
            result = run_active_sweep_multi(
                _cfg_immediate_offline(), store, Allowlist.load(None), SignatureSet.load(),
                interfaces=["eth0", "eth0.10"],
            )
            statuses = {mac: store.get_device(mac).status for mac in ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")}
            store.close()
        assert not any(e.event_type == "disconnected" for e in result.events)
        assert statuses == {"aa:bb:cc:dd:ee:ff": "online", "11:22:33:44:55:66": "online"}


def test_run_active_sweep_multi_still_detects_a_real_disconnect_on_its_own_interface(tmp_path: Path):
    a = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    b = scanner.ArpSighting(mac="11:22:33:44:55:66", ip="192.168.10.7", seen_at=_now())

    db_path = tmp_path / "db.sqlite"
    for by_interface in ({"eth0": [a], "eth0.10": [b]}, {"eth0": [a], "eth0.10": []}):
        with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
             patch.object(scanner, "local_subnet", side_effect=_SUBNETS.get), \
             patch.object(scanner, "active_scan", side_effect=_per_interface_scan(by_interface)), \
             patch.object(scanner, "active_scan_v6", return_value=[]):
            store = DeviceStore(db_path)
            result = run_active_sweep_multi(
                _cfg_immediate_offline(), store, Allowlist.load(None), SignatureSet.load(),
                interfaces=["eth0", "eth0.10"],
            )
            statuses = {mac: store.get_device(mac).status for mac in ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")}
            store.close()

    assert statuses == {"aa:bb:cc:dd:ee:ff": "online", "11:22:33:44:55:66": "offline"}
    assert [e.mac for e in result.events if e.event_type == "disconnected"] == ["11:22:33:44:55:66"]


def test_coalesce_sightings_keeps_the_same_sighting_on_different_interfaces_apart():
    now = _now()
    on_eth0 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=now, interface="eth0")
    on_vlan = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=now, interface="eth0.10")
    assert coalesce_sightings([on_eth0, on_vlan, on_eth0]) == [on_eth0, on_vlan]


def test_apply_self_trust_trusts_this_host_on_every_listed_interface():
    macs = {"eth0": "02:00:00:00:00:01", "eth0.10": "02:00:00:00:00:02"}
    allowlist = Allowlist.load(None)
    with patch.object(scanner, "local_mac", side_effect=macs.get):
        apply_self_trust(allowlist, interface=["eth0", "eth0.10"])
    assert allowlist.match("02:00:00:00:00:01") is not None
    assert allowlist.match("02:00:00:00:00:02") is not None


# --- offline retry probe (scan.offline_retry_probe) -------------------------


def _cfg_immediate_offline_with_retry() -> Config:
    cfg = Config()
    cfg.scan.ipv6 = False
    cfg.scan.offline_grace_seconds = 0
    cfg.scan.offline_after_missed_scans = 1
    cfg.scan.offline_retry_probe = True
    cfg.scan.offline_retry_timeout_seconds = 1.0
    return cfg


def _seed_one_online_device(db_path: Path, cfg: Config) -> None:
    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]), \
         patch.object(scanner, "active_scan_v6", return_value=[]):
        store = DeviceStore(db_path)
        run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.close()


def test_offline_retry_probe_answering_device_stays_online(tmp_path: Path):
    """A device missed by the broadcast sweep, but that answers the
    unicast retry probe, must not be disconnected - it's folded back in
    as a real sighting instead, exactly like any other positive sighting."""

    db_path = tmp_path / "db.sqlite"
    cfg = _cfg_immediate_offline_with_retry()
    _seed_one_online_device(db_path, cfg)

    reply = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", return_value=[]), \
         patch.object(scanner, "arp_probe", return_value=reply) as probe_mock:
        store = DeviceStore(db_path)
        result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        status = store.get_device("aa:bb:cc:dd:ee:ff").status
        store.close()

    probe_mock.assert_called_once_with("192.168.1.5", interface="eth0", timeout=1.0)
    assert status == "online"
    assert not any(e.event_type == "disconnected" for e in result.events)
    assert "aa:bb:cc:dd:ee:ff" in {d.mac for d in result.devices}


def test_offline_retry_probe_no_answer_still_disconnects(tmp_path: Path):
    """The retry is only a rescue - a device that also fails to answer the
    direct probe is disconnected exactly as it would have been without
    this feature."""

    db_path = tmp_path / "db.sqlite"
    cfg = _cfg_immediate_offline_with_retry()
    _seed_one_online_device(db_path, cfg)

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", return_value=[]), \
         patch.object(scanner, "arp_probe", return_value=None) as probe_mock:
        store = DeviceStore(db_path)
        result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        status = store.get_device("aa:bb:cc:dd:ee:ff").status
        store.close()

    probe_mock.assert_called_once()
    assert status == "offline"
    assert any(e.event_type == "disconnected" for e in result.events)


def test_offline_retry_probe_disabled_never_calls_arp_probe(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    cfg = _cfg_immediate_offline_with_retry()
    cfg.scan.offline_retry_probe = False
    _seed_one_online_device(db_path, cfg)

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", return_value=[]), \
         patch.object(scanner, "arp_probe") as probe_mock:
        store = DeviceStore(db_path)
        result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        status = store.get_device("aa:bb:cc:dd:ee:ff").status
        store.close()

    probe_mock.assert_not_called()
    assert status == "offline"
    assert any(e.event_type == "disconnected" for e in result.events)


def test_offline_retry_probe_unavailable_does_not_crash_sweep(tmp_path: Path):
    """A ScannerUnavailable from the retry probe (e.g. lost root mid-run)
    must not crash the sweep or block the normal offline transition for
    the device that couldn't be retried."""

    db_path = tmp_path / "db.sqlite"
    cfg = _cfg_immediate_offline_with_retry()
    _seed_one_online_device(db_path, cfg)

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", return_value=[]), \
         patch.object(scanner, "arp_probe", side_effect=scanner.ScannerUnavailable("no root")):
        store = DeviceStore(db_path)
        result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        status = store.get_device("aa:bb:cc:dd:ee:ff").status
        store.close()

    assert status == "offline"
    assert any(e.event_type == "disconnected" for e in result.events)
    assert result.errors == []  # a retry-probe failure isn't a sweep-wide error


def test_offline_retry_probe_skips_device_with_no_ipv4_address(tmp_path: Path):
    """An IPv6-only device has nothing for a unicast ARP probe to target -
    skipped, not probed, and disconnects normally if actually missed."""

    db_path = tmp_path / "db.sqlite"
    cfg = _cfg_immediate_offline_with_retry()
    cfg.scan.ipv6 = True
    v6 = scanner.ArpSighting(mac="11:22:33:44:55:66", ip="fe80::1", seen_at=_now())
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", return_value=[v6]):
        store = DeviceStore(db_path)
        run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.close()

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch.object(scanner, "active_scan_v6", return_value=[]), \
         patch.object(scanner, "arp_probe") as probe_mock:
        store = DeviceStore(db_path)
        result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        status = store.get_device("11:22:33:44:55:66").status
        store.close()

    probe_mock.assert_not_called()
    assert status == "offline"
    assert any(e.event_type == "disconnected" for e in result.events)


def test_run_active_sweep_respects_grace_period_across_multiple_sweeps(tmp_path: Path):
    """Integration test: with the default-shaped grace config, a device
    misses two sweeps and stays online, then a third eligible miss (with the
    grace period also elapsed) actually disconnects it."""

    db_path = tmp_path / "db.sqlite"
    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    cfg = Config()
    cfg.scan.ipv6 = False
    cfg.scan.offline_grace_seconds = 0
    cfg.scan.offline_after_missed_scans = 3
    cfg.scan.offline_retry_probe = False  # not under test here - see test_offline_retry_* below

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]):
        store = DeviceStore(db_path)
        run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.close()

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]):
        store = DeviceStore(db_path)
        for _ in range(2):
            result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                       interface="eth0", subnet="192.168.1.0/24")
            assert result.events == []
            assert store.get_device("aa:bb:cc:dd:ee:ff").status == "online"

        result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        store.close()

    assert any(e.event_type == "disconnected" for e in result.events)


def test_run_active_sweep_records_ipv4_and_ipv6_coverage_independently(tmp_path: Path):
    """A device seen via both IPv4 and IPv6 in one sweep, then missed by
    IPv6 only in the next, must not be disconnected - both known paths are
    required (see DeviceStore.mark_offline)."""

    db_path = tmp_path / "db.sqlite"
    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    v6 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="fe80::1", seen_at=_now())
    cfg = Config()
    cfg.scan.offline_grace_seconds = 0
    cfg.scan.offline_after_missed_scans = 1
    cfg.scan.offline_retry_probe = False  # not under test here - see test_offline_retry_* below

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]), \
         patch.object(scanner, "active_scan_v6", return_value=[v6]):
        store = DeviceStore(db_path)
        run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.close()

    # Next sweep: IPv4 still sees it, IPv6 sweep runs but doesn't - since the
    # active-scan merge treats "seen at all" as online for this tick, no miss
    # is recorded regardless (any positive sighting keeps a device online).
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]), \
         patch.object(scanner, "active_scan_v6", return_value=[]):
        store = DeviceStore(db_path)
        result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        status = store.get_device("aa:bb:cc:dd:ee:ff").status
        store.close()

    assert status == "online"
    assert result.events == []


def test_run_active_sweep_availability_finding_after_delay_elapses(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    cfg = Config()
    cfg.scan.ipv6 = False
    cfg.scan.offline_grace_seconds = 0
    cfg.scan.offline_after_missed_scans = 1
    cfg.scan.offline_retry_probe = False  # not under test here - see test_offline_retry_* below

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]):
        store = DeviceStore(db_path)
        t0 = _now()
        run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=t0)
        # A per-device override, decoupled from the (0s) disconnect grace
        # above, so this test controls availability timing independently.
        store.set_offline_after("aa:bb:cc:dd:ee:ff", 1.5, updated_at=t0)
        store.close()

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch("lanfence.engine.utcnow", return_value=t0 + timedelta(seconds=1)):
        store = DeviceStore(db_path)
        first = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                  interface="eth0", subnet="192.168.1.0/24")
        store.close()

    assert any(e.event_type == "disconnected" for e in first.events)
    assert [f for f in first.findings if f.kind == "availability"] == []  # 1s < 1.5s override

    # A later eligible sweep, past the 1.5s override, evaluates the pending
    # availability alert without requiring another disconnect.
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch("lanfence.engine.utcnow", return_value=t0 + timedelta(seconds=2)):
        store = DeviceStore(db_path)
        second = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        store.close()

    availability = [f for f in second.findings if f.kind == "availability"]
    assert len(availability) == 1
    assert availability[0].severity == "medium"


def test_evaluate_availability_evidence_includes_vendor_and_metadata(tmp_path: Path):
    db_path = tmp_path / "db.sqlite"
    v4 = scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.5", seen_at=_now())
    cfg = Config()
    cfg.scan.ipv6 = False
    cfg.scan.offline_grace_seconds = 0
    cfg.scan.offline_after_missed_scans = 1
    cfg.scan.offline_retry_probe = False

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[v4]):
        store = DeviceStore(db_path)
        t0 = _now()
        run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                          interface="eth0", subnet="192.168.1.0/24")
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=t0)
        store.set_offline_after("aa:bb:cc:dd:ee:ff", 0.0, updated_at=t0)
        store.update_device_metadata(
            "aa:bb:cc:dd:ee:ff", owner="Emily", location="Home office", updated_at=t0,
        )
        store.close()

    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None), \
         patch.object(scanner, "active_scan", return_value=[]), \
         patch("lanfence.engine.utcnow", return_value=t0 + timedelta(seconds=1)):
        store = DeviceStore(db_path)
        result = run_active_sweep(cfg, store, Allowlist.load(None), SignatureSet.load(),
                                   interface="eth0", subnet="192.168.1.0/24")
        store.close()

    availability = [f for f in result.findings if f.kind == "availability"]
    assert len(availability) == 1
    assert "IP: 192.168.1.5" in availability[0].evidence
    assert "Owner: Emily" in availability[0].evidence
    assert "Location: Home office" in availability[0].evidence


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


def test_filter_rate_limited_recovery_not_swallowed_by_recent_absence_alert(tmp_path: Path):
    """Regression test: an availability absence alert and its recovery for
    the same MAC must not share a cooldown lane - a recovery firing moments
    after the absence alert must still get through."""

    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_rate_limit(900)
    t0 = _now()
    absence = Finding(mac="aa:bb:cc:dd:ee:ff", title="absent", severity="medium", kind="availability")
    recovery = Finding(mac="aa:bb:cc:dd:ee:ff", title="recovered", severity="info", kind="availability")

    kept_absence = filter_rate_limited([absence], store, cfg.alerts, now=t0)
    kept_recovery = filter_rate_limited([recovery], store, cfg.alerts, now=t0 + timedelta(seconds=1))
    store.close()

    assert kept_absence == [absence]
    assert kept_recovery == [recovery]


def test_filter_rate_limited_still_cools_down_repeated_security_findings_by_mac(tmp_path: Path):
    """Non-availability findings keep their existing plain-mac cooldown key -
    unchanged behavior for everything that isn't an availability finding."""

    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_rate_limit(900)
    t0 = _now()
    first = Finding(mac="aa:bb:cc:dd:ee:ff", title="a", severity="medium", kind="security")
    second = Finding(mac="aa:bb:cc:dd:ee:ff", title="b", severity="medium", kind="security")

    kept_first = filter_rate_limited([first], store, cfg.alerts, now=t0)
    kept_second = filter_rate_limited([second], store, cfg.alerts, now=t0 + timedelta(seconds=1))
    store.close()

    assert kept_first == [first]
    assert kept_second == []


def test_filter_rate_limited_network_service_finding_cooldown_by_subject(tmp_path: Path):
    """A network-service finding (no MAC) still gets real cooldown
    bookkeeping, keyed by its subject_id rather than crashing on a missing
    MAC."""

    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_rate_limit(900)
    t0 = _now()
    first = Finding(
        mac=None, title="Unexpected DHCP server observed", severity="medium",
        kind="network_service", subject_id="eth0/192.168.1.66",
    )
    second = Finding(
        mac=None, title="Unexpected DHCP server observed", severity="medium",
        kind="network_service", subject_id="eth0/192.168.1.66",
    )
    different_subject = Finding(
        mac=None, title="Unexpected DHCP server observed", severity="medium",
        kind="network_service", subject_id="eth0/10.0.0.5",
    )

    kept_first = filter_rate_limited([first], store, cfg.alerts, now=t0)
    kept_second = filter_rate_limited([second], store, cfg.alerts, now=t0 + timedelta(seconds=1))
    kept_different = filter_rate_limited([different_subject], store, cfg.alerts, now=t0 + timedelta(seconds=1))
    store.close()

    assert kept_first == [first]
    assert kept_second == []  # same subject, within cooldown
    assert kept_different == [different_subject]  # different subject - independent


# --- filter_rate_limited: global budget (defeats MAC-rotation flooding) -----


def _cfg_with_global_limit(max_per_window: int, window_seconds: float = 60.0) -> Config:
    cfg = Config()
    cfg.alerts.rate_limit_seconds = 900.0
    cfg.alerts.global_rate_limit_max = max_per_window
    cfg.alerts.global_rate_limit_window_seconds = window_seconds
    return cfg


def test_filter_rate_limited_global_budget_caps_total_volume_across_distinct_macs(tmp_path: Path):
    """The per-MAC cooldown alone would let every one of these findings
    through (each MAC is new to alert_log) - the global budget must still
    cap total dispatch volume regardless of how many distinct MACs are
    involved (e.g. a MAC-rotation flood)."""

    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_global_limit(5)
    findings = [
        Finding(mac=f"aa:bb:cc:dd:ee:{i:02x}", title="Unknown device connected", severity="medium")
        for i in range(50)
    ]
    kept = filter_rate_limited(findings, store, cfg.alerts, now=_now())
    store.close()

    assert len(kept) == 5


def test_filter_rate_limited_global_budget_zero_disables_it(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_global_limit(0)
    findings = [
        Finding(mac=f"aa:bb:cc:dd:ee:{i:02x}", title="Unknown device connected", severity="medium")
        for i in range(30)
    ]
    kept = filter_rate_limited(findings, store, cfg.alerts, now=_now())
    store.close()

    assert len(kept) == 30


def test_filter_rate_limited_global_budget_still_applies_to_escalations(tmp_path: Path):
    """An escalation bypasses its own per-MAC cooldown, but must not be a
    way to bypass the global cap once it's exhausted."""

    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_global_limit(1)
    t0 = _now()
    low = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="info")
    other_low = Finding(mac="11:22:33:44:55:66", title="t", severity="info")
    escalated = Finding(mac="aa:bb:cc:dd:ee:ff", title="t escalated", severity="high")

    kept_first = filter_rate_limited([low], store, cfg.alerts, now=t0)
    # Global budget (max 1) is now exhausted for this window.
    kept_other = filter_rate_limited([other_low], store, cfg.alerts, now=t0)
    kept_escalation = filter_rate_limited([escalated], store, cfg.alerts, now=t0)
    store.close()

    assert kept_first == [low]
    assert kept_other == []
    assert kept_escalation == []  # per-MAC cooldown says yes, global budget says no


def test_filter_rate_limited_global_budget_resets_after_its_window(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    cfg = _cfg_with_global_limit(1, window_seconds=30.0)
    t0 = _now()
    a = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="medium")
    b = Finding(mac="11:22:33:44:55:66", title="t", severity="medium")
    c = Finding(mac="77:88:99:aa:bb:cc", title="t", severity="medium")

    kept_a = filter_rate_limited([a], store, cfg.alerts, now=t0)
    kept_b = filter_rate_limited([b], store, cfg.alerts, now=t0 + timedelta(seconds=5))
    kept_c = filter_rate_limited([c], store, cfg.alerts, now=t0 + timedelta(seconds=31))
    store.close()

    assert kept_a == [a]
    assert kept_b == []
    assert kept_c == [c]


# --- coalesce_sightings ------------------------------------------------


def _sighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=None, hostname=None, source="arp"):
    return scanner.ArpSighting(mac=mac, ip=ip, seen_at=seen_at or _now(), hostname=hostname, source=source)


def test_coalesce_sightings_collapses_pure_duplicates_to_the_latest():
    t0 = _now()
    sightings = [_sighting(seen_at=t0 + timedelta(seconds=i)) for i in range(10)]
    result = coalesce_sightings(sightings)
    assert len(result) == 1
    assert result[0].seen_at == sightings[-1].seen_at


def test_coalesce_sightings_preserves_distinct_ip_for_same_mac():
    """A dual-stack device's two distinct addresses must both survive."""

    t0 = _now()
    sightings = [
        _sighting(ip="10.0.0.5", seen_at=t0),
        _sighting(ip="fe80::1", seen_at=t0),
    ]
    result = coalesce_sightings(sightings)
    assert {s.ip for s in result} == {"10.0.0.5", "fe80::1"}


def test_coalesce_sightings_preserves_distinct_hostname():
    t0 = _now()
    sightings = [
        _sighting(hostname="old-name", seen_at=t0),
        _sighting(hostname="new-name", seen_at=t0 + timedelta(seconds=1)),
    ]
    result = coalesce_sightings(sightings)
    assert {s.hostname for s in result} == {"old-name", "new-name"}


def test_coalesce_sightings_preserves_distinct_macs():
    t0 = _now()
    sightings = [_sighting(mac=f"aa:bb:cc:dd:ee:{i:02x}", seen_at=t0) for i in range(20)]
    result = coalesce_sightings(sightings)
    assert len(result) == 20


def test_coalesce_sightings_preserves_first_occurrence_order_for_distinct_keys():
    t0 = _now()
    sightings = [
        _sighting(mac="aa:bb:cc:dd:ee:01", seen_at=t0),
        _sighting(mac="aa:bb:cc:dd:ee:02", seen_at=t0),
        _sighting(mac="aa:bb:cc:dd:ee:01", seen_at=t0 + timedelta(seconds=5)),  # duplicate of #1
    ]
    result = coalesce_sightings(sightings)
    assert [s.mac for s in result] == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    assert result[0].seen_at == t0 + timedelta(seconds=5)  # the later duplicate wins


def test_coalesce_sightings_empty_input():
    assert coalesce_sightings([]) == []


# --- filter_snoozed ------------------------------------------------------


def test_filter_snoozed_passes_through_findings_with_no_mac(tmp_path: Path):
    """Snoozing is a per-device concept and can't apply to a finding that
    isn't about any one device."""

    store = DeviceStore(tmp_path / "db.sqlite")
    now = _now()
    finding = Finding(
        mac=None, title="Unexpected DHCP server observed", severity="medium",
        kind="network_service", subject_id="eth0/192.168.1.66",
    )

    kept = filter_snoozed([finding], store, now=now)
    store.close()
    assert kept == [finding]


def test_filter_snoozed_removes_findings_for_a_snoozed_mac(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    now = _now()
    store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now + timedelta(hours=1), updated_at=now)
    finding = Finding(mac="aa:bb:cc:dd:ee:ff", title="t", severity="high")

    kept = filter_snoozed([finding], store, now=now)
    store.close()
    assert kept == []


def test_filter_snoozed_also_suppresses_availability_findings_dispatch(tmp_path: Path):
    """An always-on device's availability finding is still generated (still
    visible in CLI/JSON/history) even when snoozed - snoozing only ever
    suppresses external dispatch, and that applies uniformly regardless of
    finding kind."""

    store = DeviceStore(tmp_path / "db.sqlite")
    now = _now()
    store.set_snoozed("aa:bb:cc:dd:ee:ff", until=now + timedelta(hours=1), updated_at=now)
    absence = Finding(mac="aa:bb:cc:dd:ee:ff", title="absent", severity="medium", kind="availability")

    kept = filter_snoozed([absence], store, now=now)
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


# --- apply_self_trust ---------------------------------------------------


def test_apply_self_trust_adds_own_mac_when_detected():
    allowlist = Allowlist.load(None)
    with patch("lanfence.engine.scanner.local_mac", return_value="aa:bb:cc:dd:ee:ff"):
        apply_self_trust(allowlist, interface="eth0")

    entry = allowlist.match("aa:bb:cc:dd:ee:ff")
    assert entry is not None
    assert "lanfence" in entry.name.lower() or "host" in entry.name.lower()


def test_apply_self_trust_is_a_noop_when_mac_cannot_be_determined():
    allowlist = Allowlist.load(None)
    with patch("lanfence.engine.scanner.local_mac", return_value=None):
        apply_self_trust(allowlist, interface="eth0")

    assert len(allowlist) == 0


def test_apply_self_trust_never_overrides_an_existing_operator_entry():
    allowlist = Allowlist.load(None)
    allowlist.add("aa:bb:cc:dd:ee:ff", "My Own Custom Name", "operator-chosen")
    with patch("lanfence.engine.scanner.local_mac", return_value="aa:bb:cc:dd:ee:ff"):
        apply_self_trust(allowlist, interface="eth0")

    entry = allowlist.match("aa:bb:cc:dd:ee:ff")
    assert entry.name == "My Own Custom Name"


def test_apply_self_trust_never_saves_to_disk(tmp_path: Path):
    allowlist_path = tmp_path / "allowlist.yaml"
    allowlist = Allowlist.load(allowlist_path)
    allowlist.path = allowlist_path
    with patch("lanfence.engine.scanner.local_mac", return_value="aa:bb:cc:dd:ee:ff"):
        apply_self_trust(allowlist, interface="eth0")

    assert not allowlist_path.exists()  # in-memory only - apply_self_trust itself never calls save()


def test_apply_self_trust_makes_own_findings_info_severity(tmp_path: Path, monkeypatch):
    """End-to-end: once trusted, LAN Fence's own MAC produces the same
    downgraded-to-info finding any other allowlisted device would."""

    monkeypatch.setattr("lanfence.engine.scanner.resolve_hostname", lambda ip, timeout=1.0: None)
    allowlist = Allowlist.load(None)
    with patch("lanfence.engine.scanner.local_mac", return_value="aa:bb:cc:dd:ee:ff"):
        apply_self_trust(allowlist, interface="eth0")

    store = DeviceStore(tmp_path / "db.sqlite")
    device, event_type, findings = process_sighting(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now(),
        store=store, allowlist=allowlist, signatures=SignatureSet.load(), cfg=Config(),
    )
    store.close()

    assert event_type == "new_device"
    assert device.allowlisted is True
    assert findings[0].severity == "info"


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


def test_build_inventory_joins_presence_policy(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    now = _now()
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.1", hostname=None, vendor=None, seen_at=now)
    store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=now)
    store.set_offline_after("aa:bb:cc:dd:ee:ff", 600.0, updated_at=now)

    inventory = build_inventory(store, Allowlist.load(None))
    store.close()

    device = inventory[0]
    assert device.presence_policy == "always-on"
    assert device.offline_after_seconds == 600.0


# --- enrich_missing_hostnames -----------------------------------------


def test_enrich_missing_hostnames_resolves_online_device_without_one():
    device = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", status="online", first_seen=_now(), last_seen=_now())
    with patch("lanfence.engine.scanner.resolve_hostname", return_value="phone.local") as resolve_mock:
        result = enrich_missing_hostnames([device], resolve=True, timeout=1.0)
    assert result[0].hostname == "phone.local"
    resolve_mock.assert_called_once_with("10.0.0.5", timeout=1.0)


def test_enrich_missing_hostnames_skips_device_that_already_has_one():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="already-known", status="online",
        first_seen=_now(), last_seen=_now(),
    )
    with patch("lanfence.engine.scanner.resolve_hostname") as resolve_mock:
        result = enrich_missing_hostnames([device], resolve=True, timeout=1.0)
    assert result[0].hostname == "already-known"
    resolve_mock.assert_not_called()


def test_enrich_missing_hostnames_skips_offline_device():
    # An offline device's last-known IP may have been reassigned by DHCP -
    # a lookup on it could return a different device's hostname.
    device = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", status="offline", first_seen=_now(), last_seen=_now())
    with patch("lanfence.engine.scanner.resolve_hostname") as resolve_mock:
        result = enrich_missing_hostnames([device], resolve=True, timeout=1.0)
    assert result[0].hostname is None
    resolve_mock.assert_not_called()


def test_enrich_missing_hostnames_skips_device_without_ip():
    device = Device(mac="aa:bb:cc:dd:ee:ff", ip=None, status="online", first_seen=_now(), last_seen=_now())
    with patch("lanfence.engine.scanner.resolve_hostname") as resolve_mock:
        result = enrich_missing_hostnames([device], resolve=True, timeout=1.0)
    assert result[0].hostname is None
    resolve_mock.assert_not_called()


def test_enrich_missing_hostnames_noop_when_resolve_false():
    device = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", status="online", first_seen=_now(), last_seen=_now())
    with patch("lanfence.engine.scanner.resolve_hostname") as resolve_mock:
        result = enrich_missing_hostnames([device], resolve=False, timeout=1.0)
    assert result[0].hostname is None
    resolve_mock.assert_not_called()


def test_enrich_missing_hostnames_keeps_none_when_lookup_fails():
    device = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", status="online", first_seen=_now(), last_seen=_now())
    with patch("lanfence.engine.scanner.resolve_hostname", return_value=None):
        result = enrich_missing_hostnames([device], resolve=True, timeout=1.0)
    assert result[0].hostname is None


def test_enrich_missing_hostnames_never_mutates_input_list():
    device = Device(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", status="online", first_seen=_now(), last_seen=_now())
    devices = [device]
    with patch("lanfence.engine.scanner.resolve_hostname", return_value="phone.local"):
        result = enrich_missing_hostnames(devices, resolve=True, timeout=1.0)
    assert devices[0].hostname is None  # original untouched
    assert result[0].hostname == "phone.local"
    assert result is not devices


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
