from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from lanfence import scanner


def _now():
    return datetime.now(timezone.utc)


def test_dedupe_latest_keeps_most_recent_and_normalizes_mac():
    t0 = _now()
    sightings = [
        scanner.ArpSighting(mac="AA:BB:CC:DD:EE:FF", ip="1.1.1.1", seen_at=t0),
        scanner.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="1.1.1.2", seen_at=t0 + timedelta(seconds=5)),
    ]
    latest = scanner.dedupe_latest(sightings)
    assert list(latest.keys()) == ["aa:bb:cc:dd:ee:ff"]
    assert latest["aa:bb:cc:dd:ee:ff"].ip == "1.1.1.2"


def test_dedupe_latest_drops_unparseable_mac():
    sightings = [scanner.ArpSighting(mac="not-a-mac", ip="1.1.1.1", seen_at=_now())]
    assert scanner.dedupe_latest(sightings) == {}


@pytest.mark.parametrize(
    "exc,expected",
    [
        (PermissionError("nope"), True),
        (OSError(1, "Operation not permitted"), True),  # errno.EPERM
        (RuntimeError("Permission denied: could not open /dev/bpf0"), True),
        (ValueError("some other problem"), False),
    ],
)
def test_looks_like_permission_error(exc, expected):
    if isinstance(exc, OSError) and not isinstance(exc, PermissionError):
        exc.errno = 1  # errno.EPERM, to exercise the OSError branch directly
    assert scanner._looks_like_permission_error(exc) is expected


def test_active_scan_rejects_bad_subnet():
    with pytest.raises(ValueError):
        scanner.active_scan(subnet="not-a-subnet")


def test_local_subnet_returns_none_when_scanner_unavailable(monkeypatch):
    def _boom():
        raise scanner.ScannerUnavailable("no scapy")

    monkeypatch.setattr(scanner, "_require_scapy", _boom)
    assert scanner.local_subnet("eth0") is None
    assert scanner.default_interface() is None


def test_resolve_hostname_returns_none_on_failure():
    # 192.0.2.0/24 is TEST-NET-1 (RFC 5737) - guaranteed not to resolve.
    assert scanner.resolve_hostname("192.0.2.123", timeout=0.5) is None
