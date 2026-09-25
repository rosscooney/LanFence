from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lanfence.changes import (
    day_heading,
    describe,
    is_admin_service,
    normalize_mdns_type,
    service_label,
    significance_at_least,
)
from lanfence.models import CHANGE_TYPES, ChangeEvent

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)


def _event(change_type, **kwargs):
    return ChangeEvent(mac="00:11:32:aa:bb:01", change_type=change_type, occurred_at=NOW, source="test", **kwargs)


def test_service_labels_read_like_plain_language():
    assert service_label("port", "tcp/22") == "SSH / TCP 22"
    assert service_label("port", "tcp/12345") == "TCP 12345"
    assert service_label("mdns", "_ssh._tcp") == "SSH (mDNS _ssh._tcp)"
    assert service_label("mdns", "_ipp._tcp") == "Printing (mDNS _ipp._tcp)"
    assert service_label("mdns", "_obscure._tcp") == "mDNS _obscure._tcp"
    assert service_label("ipv6_prefix", "2001:db8::/64") == "IPv6 network 2001:db8::/64"


def test_mdns_types_normalise_case_and_domain():
    assert normalize_mdns_type("_SSH._tcp.local.") == "_ssh._tcp"
    assert normalize_mdns_type("_http._tcp") == "_http._tcp"


def test_admin_services():
    assert is_admin_service("port", "tcp/22")
    assert is_admin_service("port", "tcp/3389")
    assert is_admin_service("mdns", "_rfb._tcp")
    assert not is_admin_service("port", "tcp/443")
    assert not is_admin_service("mdns", "_airplay._tcp")
    assert not is_admin_service("ipv6_prefix", "2001:db8::/64")


def test_new_service_description_explains_the_baseline_and_history():
    text = describe(_event(
        "service_new", signal="port", subject="tcp/22",
        current={"baseline": ["HTTPS / TCP 443", "SMB / TCP 445"], "monitored_days": 127.3, "established": True},
    ))
    assert text.title == "New service detected: SSH / TCP 22"
    assert "Previous baseline: HTTPS / TCP 443, SMB / TCP 445" in text.details
    assert "SSH has not been part of this device's baseline during 127 days of monitoring." in text.details


def test_descriptions_never_claim_malice():
    for change_type in CHANGE_TYPES:
        text = describe(_event(change_type, signal="port", subject="tcp/22"))
        assert text.title
        combined = " ".join([text.title, *text.details]).lower()
        assert "malicious" not in combined and "compromis" not in combined and "attack" not in combined


def test_risk_change_description():
    text = describe(_event("risk_changed", previous={"score": 12, "level": "low"},
                           current={"score": 57, "level": "high"}))
    assert text.title == "Risk changed: LOW 12 -> HIGH 57"


def test_significance_ordering():
    assert significance_at_least("high", "medium")
    assert not significance_at_least("low", "medium")
    assert significance_at_least("critical", "critical")


def test_day_headings():
    assert day_heading(NOW, now=NOW) == "Today"
    assert day_heading(NOW - timedelta(days=1), now=NOW) == "Yesterday"
    assert day_heading(NOW - timedelta(days=5), now=NOW).endswith("2026")


def test_needs_attention():
    event = _event("service_new")
    assert event.needs_attention(now=NOW)
    assert not event.model_copy(update={"review_state": "accepted"}).needs_attention(now=NOW)
    assert not event.model_copy(update={"suppressed": True}).needs_attention(now=NOW)
    snoozed = event.model_copy(update={"review_state": "snoozed", "snoozed_until": NOW + timedelta(hours=1)})
    assert not snoozed.needs_attention(now=NOW)
    assert snoozed.needs_attention(now=NOW + timedelta(hours=2))
