from __future__ import annotations

from datetime import datetime, timezone

from lanfence.models import Device, Finding, ScanResult
from lanfence.report import exit_code_for, exit_code_for_findings, highest_severity, render_scan_result


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
