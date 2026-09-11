from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lanfence.models import Device, DeviceEvent, Finding, ScanResult
from lanfence.report import (
    exit_code_for,
    exit_code_for_findings,
    highest_severity,
    render_device_detail,
    render_device_inventory,
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
