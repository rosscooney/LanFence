from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from lanfence.allowlist import Allowlist
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.engine import build_findings, process_sighting
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
