from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lanfence.models import Device, DeviceEvent, Digest, DigestActivity, DigestDeviceEntry, DigestSection, Finding, ScanResult
from lanfence.report import (
    exit_code_for,
    exit_code_for_findings,
    highest_severity,
    presence_label,
    render_device_detail,
    render_device_inventory,
    render_digest,
    render_findings,
    render_scan_result,
    review_status_label,
)


def _now():
    return datetime.now(timezone.utc)


def _finding(severity, mac="aa:bb:cc:dd:ee:ff"):
    return Finding(mac=mac, title="t", severity=severity)


def test_highest_severity_picks_the_worst():
    assert highest_severity([_finding("info"), _finding("high"), _finding("medium")]) == "high"
    assert highest_severity([_finding("info")]) == "info"
    assert highest_severity([]) is None


def test_exit_code_for_findings():
    assert exit_code_for_findings([]) == 0
    assert exit_code_for_findings([_finding("info")]) == 0
    assert exit_code_for_findings([_finding("medium")]) == 10
    assert exit_code_for_findings([_finding("high")]) == 20


def test_exit_code_for_scan_result():
    result = ScanResult(started_at=_now(), ended_at=_now(), findings=[_finding("high")])
    assert exit_code_for(result) == 20
    clean = ScanResult(started_at=_now(), ended_at=_now())
    assert exit_code_for(clean) == 0


def test_render_findings_handles_a_finding_with_no_mac(capsys):
    finding = Finding(
        mac=None, title="Unexpected DHCP server observed", severity="medium",
        kind="network_service", subject_id="eth0/192.168.1.66",
    )
    text = render_findings([finding], plain=True)
    assert "eth0/192.168.1.66" in text  # subject shown in place of a MAC
    assert "None" not in text


def test_render_scan_result_plain_does_not_raise(capsys):
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now())
    result = ScanResult(
        started_at=_now(), ended_at=_now(), interface="eth0", subnet="10.0.0.0/24",
        devices=[device], findings=[_finding("medium")],
    )
    text = render_scan_result(result, plain=True)
    assert "LAN Fence scan result" in text
    assert "aa:bb:cc:dd:ee:ff" in text
    captured = capsys.readouterr()
    assert "LAN Fence scan result" in captured.out


def test_render_scan_result_with_errors_plain(capsys):
    result = ScanResult(started_at=_now(), ended_at=_now(), errors=["boom"])
    text = render_scan_result(result, plain=True)
    assert "boom" in text


# --- review_status_label ----------------------------------------------------


def test_review_status_label_trusted_takes_precedence():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(),
        allowlisted=True, review_state="investigating",
    )
    assert review_status_label(device, now=_now()) == "trusted"


def test_review_status_label_investigating():
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), review_state="investigating")
    assert review_status_label(device, now=_now()) == "investigating"


def test_review_status_label_snoozed_shows_expiry():
    now = _now()
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now,
        review_state="snoozed", snoozed_until=now + timedelta(hours=1),
    )
    label = review_status_label(device, now=now)
    assert label.startswith("snoozed until")


def test_review_status_label_expired_snooze_shows_pending():
    now = _now()
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now,
        review_state="snoozed", snoozed_until=now - timedelta(hours=1),
    )
    assert review_status_label(device, now=now) == "pending"


def test_review_status_label_pending_default():
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now())
    assert review_status_label(device, now=_now()) == "pending"


# --- render_device_inventory -------------------------------------------------


def test_render_device_inventory_plain(capsys):
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), hostname="my-host")
    text = render_device_inventory([device], now=_now(), plain=True)
    assert "aa:bb:cc:dd:ee:ff" in text
    assert "my-host" in text


def test_render_device_inventory_empty_database_message(capsys):
    render_device_inventory([], now=_now(), total_count=0, plain=False)
    captured = capsys.readouterr()
    assert "database yet" in captured.out.lower()


def test_render_device_inventory_no_filter_matches_message(capsys):
    render_device_inventory([], now=_now(), total_count=5, plain=False)
    captured = capsys.readouterr()
    assert "no devices match" in captured.out.lower()


# --- render_device_detail -----------------------------------------------


def test_render_device_detail_plain_distinguishes_current_and_timeline(capsys):
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now, hostname="my-host")
    events = [DeviceEvent(mac="aa:bb:cc:dd:ee:ff", event_type="new_device", timestamp=now, ip="10.0.0.5")]
    text = render_device_detail(device, events, now - timedelta(days=1), now=now, plain=True)
    assert "Current details" in text
    assert "Lifecycle timeline" in text
    assert "not a complete history" in text.lower()


def test_render_device_detail_empty_timeline_plain():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True)
    assert "0 event(s)" in text


# --- presence_label ----------------------------------------------------


def test_presence_label_unspecified():
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now())
    assert presence_label(device) == "Presence: unspecified"


def test_presence_label_intermittent():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), presence_policy="intermittent"
    )
    assert presence_label(device) == "Presence: intermittent"


def test_presence_label_always_on_shows_effective_duration_from_override():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(),
        presence_policy="always-on", offline_after_seconds=600.0,
    )
    label = presence_label(device, default_offline_after_seconds=180.0)
    assert "always-on" in label
    assert "600s" in label


def test_presence_label_always_on_falls_back_to_global_default():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), presence_policy="always-on",
    )
    label = presence_label(device, default_offline_after_seconds=180.0)
    assert "180s" in label


def test_render_device_inventory_shows_presence_column_plain():
    device = Device(
        mac="aa:bb:cc:dd:ee:ff", first_seen=_now(), last_seen=_now(), presence_policy="intermittent",
    )
    text = render_device_inventory([device], now=_now(), plain=True)
    assert "intermittent" in text


def test_render_device_detail_shows_presence_line_plain():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now, presence_policy="always-on")
    text = render_device_detail(
        device, [], now - timedelta(days=1), now=now, plain=True, default_offline_after_seconds=180.0
    )
    assert "Presence: always-on" in text
    assert "180s" in text


def test_render_device_detail_shows_address_and_name_evidence_plain():
    from lanfence.models import AddressEvidence, NameEvidence

    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    addresses = [
        AddressEvidence(mac=device.mac, ip="10.0.0.5", family="ipv4", interface="eth0",
                        source="arp", kind="observed", first_seen=now, last_seen=now),
        AddressEvidence(mac=device.mac, ip="fe80::1", family="ipv6", interface="eth0",
                        source="ipv6_nd", kind="observed", first_seen=now, last_seen=now),
    ]
    names = [
        NameEvidence(mac=device.mac, name="office-laptop", name_key="office-laptop",
                    source="dhcp_option_12", first_seen=now, last_seen=now),
    ]
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True,
                                addresses=addresses, names=names)
    assert "10.0.0.5" in text
    assert "fe80::1" in text
    assert "ARP" in text
    assert "IPv6 ND" in text
    assert "office-laptop" in text
    assert "DHCP option 12" in text


def test_render_device_detail_omits_evidence_sections_when_not_given():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True)
    assert "Addresses" not in text
    assert "Names (" not in text


def test_render_device_detail_empty_evidence_says_none():
    now = _now()
    device = Device(mac="aa:bb:cc:dd:ee:ff", first_seen=now, last_seen=now)
    text = render_device_detail(device, [], now - timedelta(days=1), now=now, plain=True,
                                addresses=[], names=[])
    assert "Addresses (0 retained)" in text
    assert "Names (0 retained)" in text


# --- render_digest -------------------------------------------------------


def _digest(**overrides):
    now = _now()
    base = dict(
        generated_at=now, window_start=now - timedelta(hours=24), window_end=now,
    )
    base.update(overrides)
    return Digest(**base)


def test_render_digest_plain_shows_window_and_counts(capsys):
    entry = DigestDeviceEntry(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="phone.local")
    digest = _digest(
        known_devices=3, online_devices=2,
        new_devices=DigestSection(items=[entry], total_count=1),
        activity=DigestActivity(new_device_count=1),
    )
    text = render_digest(digest, plain=True)
    assert "LAN Fence digest" in text
    assert "Known devices: 3" in text
    assert "aa:bb:cc:dd:ee:ff" in text
    assert "phone.local" in text


def test_render_digest_shows_monitoring_health_unavailable(capsys):
    digest = _digest()
    text = render_digest(digest, plain=True)
    assert "Monitoring health unavailable" in text


def test_render_digest_shows_omitted_count(capsys):
    entry = DigestDeviceEntry(mac="aa:bb:cc:dd:ee:ff")
    digest = _digest(needs_review=DigestSection(items=[entry], total_count=5, omitted_count=4))
    text = render_digest(digest, plain=True)
    assert "and 4 more" in text


def test_render_digest_empty_sections_say_none(capsys):
    digest = _digest()
    text = render_digest(digest, plain=True)
    assert "(none)" in text
