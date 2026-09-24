from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from lanfence.allowlist import Allowlist
from lanfence.classify import DeviceClassification
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.dossier import (
    DeviceDossier,
    FingerprintMatchInfo,
    build_device_dossier,
    build_triage_summary,
    review_priority,
)
from lanfence.engine import process_sighting
from lanfence.fingerprint import SignatureSet
from lanfence.identity import IdentityRuleSet
from lanfence.models import AdvertisedService, Device


def _now():
    return datetime.now(timezone.utc)


def _identity_rules() -> IdentityRuleSet:
    return IdentityRuleSet.load()


def _device(**overrides):
    base = dict(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
        status="online", first_seen=_now(), last_seen=_now(),
    )
    base.update(overrides)
    return Device(**base)


def _service(**overrides):
    base = dict(
        protocol="mdns", service_type="_raop._tcp.local.", service_label="AirPlay",
        identity="Living Room._raop._tcp.local.", first_seen=_now(), last_seen=_now(), status="current",
    )
    base.update(overrides)
    return AdvertisedService(**base)


def _dossier(**overrides) -> DeviceDossier:
    base = dict(
        device=_device(),
        classification=DeviceClassification(),
        fingerprint_matches=[],
        is_locally_administered_mac=False,
    )
    base.update(overrides)
    return DeviceDossier(**base)


# --- build_device_dossier ------------------------------------------------


def test_build_device_dossier_none_for_never_observed_mac(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    dossier = build_device_dossier(
        store, Allowlist.load(None), "aa:bb:cc:dd:ee:ff", signatures=SignatureSet.load(),
        identity_rules=_identity_rules(),
    )
    store.close()
    assert dossier is None


def test_build_device_dossier_gathers_evidence_and_classification(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    process_sighting(
        mac="b8:27:eb:11:22:33", ip="10.0.0.9", seen_at=_now(),
        store=store, allowlist=Allowlist.load(None), signatures=SignatureSet.load(), cfg=Config(),
    )
    dossier = build_device_dossier(
        store, Allowlist.load(None), "b8:27:eb:11:22:33", signatures=SignatureSet.load(),
        identity_rules=_identity_rules(),
    )
    store.close()

    assert dossier is not None
    assert dossier.device.mac == "b8:27:eb:11:22:33"
    assert any(a.ip == "10.0.0.9" for a in dossier.addresses)
    assert dossier.classification.device_type == "Raspberry Pi"
    assert dossier.classification.confidence == "high"
    assert dossier.is_locally_administered_mac is False
    assert dossier.identity.family == "Raspberry Pi"
    assert dossier.identity.category == "Development Board / SBC"
    assert dossier.identity.confidence > 0


def test_build_device_dossier_uses_passed_in_services_for_classification(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    process_sighting(
        mac="00:0e:58:11:22:33", ip="10.0.0.10", seen_at=_now(),
        store=store, allowlist=Allowlist.load(None), signatures=SignatureSet.load(), cfg=Config(),
    )
    service = _service()
    dossier = build_device_dossier(
        store, Allowlist.load(None), "00:0e:58:11:22:33", signatures=SignatureSet.load(),
        identity_rules=_identity_rules(), services=[service],
    )
    store.close()

    assert dossier is not None
    assert dossier.services == [service]
    assert "AirPlay" in dossier.observed_services_summary


def test_build_device_dossier_reuses_passed_in_device_without_a_second_lookup(tmp_path: Path):
    store = DeviceStore(tmp_path / "db.sqlite")
    process_sighting(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now(),
        store=store, allowlist=Allowlist.load(None), signatures=SignatureSet.load(), cfg=Config(),
    )
    prebuilt = _device(mac="aa:bb:cc:dd:ee:ff", hostname="already-built")
    dossier = build_device_dossier(
        store, Allowlist.load(None), "aa:bb:cc:dd:ee:ff", signatures=SignatureSet.load(),
        identity_rules=_identity_rules(), device=prebuilt, addresses=[], names=[], services=[],
    )
    store.close()
    assert dossier is not None
    assert dossier.device.hostname == "already-built"
    assert dossier.addresses == []


# --- DeviceDossier.label ---------------------------------------------------


def test_label_falls_back_to_allowlist_name_then_hostname_then_mac():
    assert _dossier(device=_device(allowlist_name="My Laptop", hostname="host")).label == "My Laptop"
    assert _dossier(device=_device(hostname="host")).label == "host"
    assert _dossier(device=_device()).label == "aa:bb:cc:dd:ee:ff"


def test_observed_services_summary_dedupes_and_skips_non_current():
    dossier = _dossier(
        services=[
            _service(service_label="AirPlay"),
            _service(service_label="AirPlay", identity="other-instance"),
            _service(service_label=None, service_type="_http._tcp.local."),
            _service(service_label="Stale", status="expired"),
        ],
    )
    assert dossier.observed_services_summary == ["AirPlay", "_http._tcp.local."]


# --- review_priority --------------------------------------------------------


def test_review_priority_rank0_for_medium_or_high_fingerprint_match():
    dossier = _dossier(
        fingerprint_matches=[
            FingerprintMatchInfo(category="c", severity="medium", title="t", description="d", evidence="e"),
        ],
        classification=DeviceClassification(device_type="Known thing", confidence="high", reasons=["x"]),
    )
    rank, label = review_priority(dossier)
    assert rank == 0
    assert label == "Priority"


def test_review_priority_rank1_for_locally_administered_mac():
    dossier = _dossier(is_locally_administered_mac=True)
    rank, label = review_priority(dossier)
    assert rank == 1
    assert label == "Priority"


def test_review_priority_rank2_for_unknown_classification():
    dossier = _dossier(classification=DeviceClassification())
    rank, label = review_priority(dossier)
    assert rank == 2
    assert label == "Needs identification"


def test_review_priority_rank3_for_low_confidence_classification():
    dossier = _dossier(classification=DeviceClassification(device_type="Apple device", confidence="low", reasons=["x"]))
    rank, label = review_priority(dossier)
    assert rank == 3
    assert label == "Needs identification"


def test_review_priority_rank4_for_known_vendor_without_corroboration():
    dossier = _dossier(
        device=_device(hostname=None),
        classification=DeviceClassification(device_type="Network printer", confidence="medium", reasons=["x"]),
    )
    rank, label = review_priority(dossier)
    assert rank == 4
    assert label == "Likely familiar"


def test_review_priority_rank5_for_known_vendor_with_hostname_corroboration():
    dossier = _dossier(
        device=_device(hostname="living-room-sonos"),
        classification=DeviceClassification(device_type="Sonos speaker", confidence="high", reasons=["x"]),
    )
    rank, label = review_priority(dossier)
    assert rank == 5
    assert label == "Likely familiar"


def test_review_priority_fingerprint_severity_takes_precedence_over_everything_else():
    # Even a well-identified, hostname-corroborated device is still rank 0
    # if it also matched a medium/high rogue-signature - security signal wins.
    dossier = _dossier(
        device=_device(hostname="living-room-sonos"),
        classification=DeviceClassification(device_type="Sonos speaker", confidence="high", reasons=["x"]),
        fingerprint_matches=[
            FingerprintMatchInfo(category="c", severity="high", title="t", description="d", evidence="e"),
        ],
    )
    rank, _label = review_priority(dossier)
    assert rank == 0


# --- build_triage_summary ---------------------------------------------------


def test_build_triage_summary_buckets_and_counts_reviewed():
    now = _now()
    straightforward = _dossier(
        device=_device(mac="11:22:33:44:55:01", hostname="host", allowlisted=True),
        classification=DeviceClassification(device_type="Sonos speaker", confidence="high", reasons=["x"]),
    )
    needs_id = _dossier(
        device=_device(mac="11:22:33:44:55:02"),
        classification=DeviceClassification(),
    )
    private_mac = _dossier(device=_device(mac="11:22:33:44:55:03"), is_locally_administered_mac=True)
    security = _dossier(
        device=_device(mac="11:22:33:44:55:04"),
        fingerprint_matches=[
            FingerprintMatchInfo(category="c", severity="high", title="t", description="d", evidence="e"),
        ],
    )

    summary = build_triage_summary([straightforward, needs_id, private_mac, security], now=now)

    assert summary.total == 4
    assert summary.straightforward == 1
    assert summary.needs_identification == 1
    assert summary.private_mac == 1
    assert summary.security_flagged == 1
    # only the allowlisted device counts as already-reviewed
    assert summary.reviewed == 1
    assert summary.pending == 3


def test_build_triage_summary_empty_inventory():
    summary = build_triage_summary([], now=_now())
    assert summary.total == 0
    assert summary.pending == 0
