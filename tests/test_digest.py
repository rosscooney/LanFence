from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from lanfence.allowlist import Allowlist
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.digest import (
    build_digest,
    dispatch_digest,
    format_digest_text,
    send_digest_discord,
    send_digest_email,
    send_digest_ntfy,
    send_digest_slack,
    send_digest_teams,
    send_digest_webhook,
)


def _now():
    return datetime.now(timezone.utc)


# --- build_digest: windowing and boundaries ---------------------------------


def test_digest_default_window_and_timestamps_consistent(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        digest = build_digest(store, Allowlist.load(None), since=t0 - timedelta(hours=24), until=t0)

    assert digest.generated_at == t0
    assert digest.window_end == t0
    assert digest.window_start == t0 - timedelta(hours=24)
    assert digest.schema_version == 1


def test_digest_new_device_exactly_at_window_boundaries_is_included(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=t0)
        digest = build_digest(store, Allowlist.load(None), since=t0, until=t0)

    assert digest.new_devices.total_count == 1


def test_digest_new_device_includes_owner_and_group_context(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=t0)
        store.update_device_metadata("aa:bb:cc:dd:ee:ff", updated_at=t0, owner="Alice", group="staff")
        digest = build_digest(store, Allowlist.load(None), since=t0, until=t0)

    entry = digest.new_devices.items[0]
    assert entry.owner == "Alice"
    assert entry.group == "staff"


def test_digest_new_device_includes_services_summary(tmp_path: Path):
    from lanfence.discovery import MdnsRecordSighting, process_mdns_record_sighting

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.50", hostname=None, vendor=None, seen_at=t0)
        for s in (
            MdnsRecordSighting(
                rtype="PTR", ttl=120, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
                family="ipv4", seen_at=t0, service_type="_ipp._tcp.local", instance_name="Office Printer",
                fq_instance="Office Printer._ipp._tcp.local",
            ),
            MdnsRecordSighting(
                rtype="SRV", ttl=120, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
                family="ipv4", seen_at=t0, fq_instance="Office Printer._ipp._tcp.local",
                target_host="printer.local", target_port=631,
            ),
            MdnsRecordSighting(
                rtype="A", ttl=120, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
                family="ipv4", seen_at=t0, address_owner="printer.local", address="192.168.1.50",
            ),
        ):
            process_mdns_record_sighting(s, store)

        digest = build_digest(store, Allowlist.load(None), since=t0, until=t0)

    entry = digest.new_devices.items[0]
    assert entry.services_summary == "Printing"


def test_digest_other_sections_never_include_services_summary(tmp_path: Path):
    """Only new-device rows carry a service summary - needs-review/
    investigating/missing-always-on rows stay terse (see
    `lanfence/digest.py`'s `_bounded_section`)."""

    from lanfence.discovery import MdnsRecordSighting, process_mdns_record_sighting

    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now() - timedelta(hours=2)
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.50", hostname=None, vendor=None, seen_at=t0)
        process_mdns_record_sighting(
            MdnsRecordSighting(
                rtype="PTR", ttl=120, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
                family="ipv4", seen_at=t0, service_type="_ipp._tcp.local", instance_name="Office Printer",
                fq_instance="Office Printer._ipp._tcp.local",
            ),
            store,
        )
        until = _now()
        digest = build_digest(store, Allowlist.load(None), since=until, until=until)  # empty window - not "new"

    assert digest.needs_review.items
    assert all(item.services_summary is None for item in digest.needs_review.items)


def test_digest_new_device_outside_window_is_excluded(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=t0)
        digest = build_digest(
            store, Allowlist.load(None), since=t0 + timedelta(seconds=1), until=t0 + timedelta(hours=1)
        )

    assert digest.new_devices.total_count == 0


def test_digest_empty_database(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        t0 = _now()
        digest = build_digest(store, Allowlist.load(None), since=t0 - timedelta(hours=24), until=t0)

    assert digest.known_devices == 0
    assert digest.online_devices == 0
    assert digest.is_empty is True


# --- build_digest: sections and current-vs-window distinction --------------


def test_digest_needs_review_includes_devices_first_seen_before_window(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        old = _now() - timedelta(days=10)
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=old)
        digest = build_digest(store, Allowlist.load(None), since=_now() - timedelta(hours=24), until=_now())

    assert digest.needs_review.total_count == 1
    assert digest.needs_review.items[0].mac == "aa:bb:cc:dd:ee:ff"


def test_digest_needs_review_excludes_trusted_and_snoozed_and_investigating(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        store.observe(mac="11:22:33:44:55:66", ip="10.0.0.6", hostname=None, vendor=None, seen_at=now)
        store.observe(mac="77:88:99:aa:bb:cc", ip="10.0.0.7", hostname=None, vendor=None, seen_at=now)
        store.set_snoozed("11:22:33:44:55:66", until=now + timedelta(hours=1), updated_at=now)
        store.set_investigating("77:88:99:aa:bb:cc", notes="hmm", updated_at=now)

        allowlist = Allowlist.load(None)
        allowlist.add("aa:bb:cc:dd:ee:ff", "Trusted")

        digest = build_digest(store, allowlist, since=now - timedelta(hours=1), until=now)

    assert digest.needs_review.total_count == 0


def test_digest_investigating_section_includes_notes_and_last_seen(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        store.set_investigating("aa:bb:cc:dd:ee:ff", notes="check this", updated_at=now)
        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(hours=1), until=now)

    entry = digest.investigating.items[0]
    assert entry.review_notes == "check this"
    assert entry.last_seen == now


def test_digest_missing_always_on_section(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now,
                      interface="eth0", subnet="10.0.0.0/24")
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=now)
        store.mark_offline(set(), as_of=now, grace_seconds=0, missed_after=1,
                            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0")

        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(hours=1), until=now)

    assert digest.missing_always_on.total_count == 1
    assert digest.missing_always_on.items[0].mac == "aa:bb:cc:dd:ee:ff"


def test_digest_missing_always_on_appears_even_if_offline_since_before_window(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        old = _now() - timedelta(days=10)
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=old,
                      interface="eth0", subnet="10.0.0.0/24")
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "always-on", updated_at=old)
        store.mark_offline(set(), as_of=old, grace_seconds=0, missed_after=1,
                            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0")

        digest = build_digest(store, Allowlist.load(None), since=_now() - timedelta(hours=1), until=_now())

    assert digest.missing_always_on.total_count == 1


def test_digest_intermittent_absence_not_reported_as_missing_always_on(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now,
                      interface="eth0", subnet="10.0.0.0/24")
        store.set_presence_policy("aa:bb:cc:dd:ee:ff", "intermittent", updated_at=now)
        store.mark_offline(set(), as_of=now, grace_seconds=0, missed_after=1,
                            ipv4_covered=True, ipv4_subnet="10.0.0.0/24", interface="eth0")

        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(hours=1), until=now)

    assert digest.missing_always_on.total_count == 0


def test_digest_current_trust_reflects_change_after_activity(tmp_path: Path):
    """Historical activity (a device becoming new in-window) must stay
    factual, but the section still shows *current* trust state, read fresh -
    trusting a device after it was recorded new doesn't rewrite history, it
    just changes what "current details" says now."""

    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        allowlist = Allowlist.load(None)
        digest_before = build_digest(store, allowlist, since=now - timedelta(hours=1), until=now)
        assert digest_before.new_devices.items[0].trusted is False

        allowlist.add("aa:bb:cc:dd:ee:ff", "Now Trusted")
        digest_after = build_digest(store, allowlist, since=now - timedelta(hours=1), until=now)

    assert digest_after.new_devices.items[0].trusted is True
    assert digest_after.new_devices.items[0].name == "Now Trusted"
    # the fact that it was new in this window is unaffected by the later trust change
    assert digest_after.new_devices.total_count == 1


# --- build_digest: dedup, ordering, and truncation --------------------------


def test_digest_deduplicates_multiple_new_device_events_for_same_mac(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        store.mark_offline(set(), as_of=now + timedelta(seconds=1), grace_seconds=0, missed_after=1)
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
                      seen_at=now + timedelta(seconds=2))

        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(seconds=1),
                               until=now + timedelta(seconds=3))

    assert digest.new_devices.total_count == 1  # only new_device counted, not the later reappeared


def test_digest_a_device_can_appear_in_multiple_sections(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(hours=1), until=now)

    assert digest.new_devices.total_count == 1
    assert digest.needs_review.total_count == 1
    assert digest.new_devices.items[0].mac == digest.needs_review.items[0].mac


def test_digest_section_truncated_with_omitted_count(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        for i in range(5):
            store.observe(mac=f"aa:bb:cc:dd:ee:{i:02x}", ip=f"10.0.0.{i}", hostname=None, vendor=None, seen_at=now)
        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(hours=1), until=now,
                               max_devices_per_section=2)

    assert digest.needs_review.total_count == 5
    assert len(digest.needs_review.items) == 2
    assert digest.needs_review.omitted_count == 3


def test_digest_section_ordering_is_stable_by_mac(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="cc:cc:cc:cc:cc:cc", ip="10.0.0.1", hostname=None, vendor=None, seen_at=now)
        store.observe(mac="aa:aa:aa:aa:aa:aa", ip="10.0.0.2", hostname=None, vendor=None, seen_at=now)
        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(hours=1), until=now)

    assert [e.mac for e in digest.needs_review.items] == ["aa:aa:aa:aa:aa:aa", "cc:cc:cc:cc:cc:cc"]


# --- build_digest: activity summary -----------------------------------------


def test_digest_activity_counts_distinct_devices_not_raw_events(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        store.mark_offline(set(), as_of=now + timedelta(seconds=1), grace_seconds=0, missed_after=1)
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
                      seen_at=now + timedelta(seconds=2))
        store.mark_offline(set(), as_of=now + timedelta(seconds=3), grace_seconds=0, missed_after=1)
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
                      seen_at=now + timedelta(seconds=4))

        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(seconds=1),
                               until=now + timedelta(seconds=5))

    assert digest.activity.reappeared_device_count == 1  # flapped twice, counted once
    assert digest.activity.disconnected_device_count == 1


def test_digest_activity_zero_when_no_events_in_window(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        old = _now() - timedelta(days=10)
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=old)
        digest = build_digest(store, Allowlist.load(None), since=_now() - timedelta(hours=1), until=_now())

    assert digest.activity.reappeared_device_count == 0
    assert digest.activity.disconnected_device_count == 0
    assert digest.activity.new_device_count == 0


# --- Digest.is_empty / omitted_capabilities ---------------------------------


def test_digest_is_empty_true_for_a_quiet_network(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        allowlist = Allowlist.load(None)
        allowlist.add("aa:bb:cc:dd:ee:ff", "Trusted")  # trusted -> not in needs_review

        digest = build_digest(store, allowlist, since=now + timedelta(hours=1), until=now + timedelta(hours=2))

    assert digest.is_empty is True


def test_digest_monitoring_health_always_unavailable_never_fabricated(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(hours=1), until=now)

    assert digest.monitoring_health == "Monitoring health unavailable"
    assert digest.is_empty is True  # unavailable health evidence never makes a digest nonempty


def test_digest_documents_omitted_capabilities(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        digest = build_digest(store, Allowlist.load(None), since=now - timedelta(hours=1), until=now)

    assert len(digest.omitted_capabilities) >= 1


# --- delivery: preview vs send, per-channel results -------------------------


def _digest(tmp_path: Path):
    with DeviceStore(tmp_path / "db.sqlite") as store:
        now = _now()
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
        return build_digest(store, Allowlist.load(None), since=now - timedelta(hours=1), until=now)


def test_format_digest_text_is_stable_and_readable(tmp_path: Path):
    digest = _digest(tmp_path)
    text = format_digest_text(digest)
    assert "LAN Fence digest" in text
    assert "aa:bb:cc:dd:ee:ff" in text


def test_send_digest_webhook_success(tmp_path: Path):
    digest = _digest(tmp_path)
    cfg = Config(alerts={"webhook": {"enabled": True, "url": "https://example.com/hook"}})

    class _FakeResp:
        def read(self):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("lanfence.digest.urllib.request.urlopen", return_value=_FakeResp()) as mock_open:
        ok = send_digest_webhook(digest, cfg)
    assert ok is True
    mock_open.assert_called_once()


def test_send_digest_webhook_reports_failure_not_success(tmp_path: Path):
    import urllib.error

    digest = _digest(tmp_path)
    cfg = Config(alerts={"webhook": {"enabled": True, "url": "https://example.com/hook"}})

    with patch("lanfence.digest.urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
        ok = send_digest_webhook(digest, cfg)
    assert ok is False


def test_send_digest_webhook_disabled_returns_false_without_network_call(tmp_path: Path):
    digest = _digest(tmp_path)
    cfg = Config(alerts={"webhook": {"enabled": False, "url": "https://example.com/hook"}})

    with patch("lanfence.digest.urllib.request.urlopen") as mock_open:
        ok = send_digest_webhook(digest, cfg)
    assert ok is False
    mock_open.assert_not_called()


def test_send_digest_email_success(tmp_path: Path):
    digest = _digest(tmp_path)
    cfg = Config(alerts={"email": {
        "enabled": True, "from_addr": "lanfence@example.com", "to_addrs": ["me@example.com"],
    }})

    with patch("lanfence.digest.smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value
        ok = send_digest_email(digest, cfg)
    assert ok is True
    instance.send_message.assert_called_once()


def test_send_digest_email_starttls_uses_a_verifying_context(tmp_path: Path):
    import ssl

    digest = _digest(tmp_path)
    cfg = Config(alerts={"email": {
        "enabled": True, "from_addr": "lanfence@example.com", "to_addrs": ["me@example.com"],
    }})

    with patch("lanfence.digest.smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value
        ok = send_digest_email(digest, cfg)
    assert ok is True
    instance.starttls.assert_called_once()
    context = instance.starttls.call_args.kwargs.get("context")
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_send_digest_email_certificate_failure_returns_false_not_raises(tmp_path: Path):
    import ssl

    digest = _digest(tmp_path)
    cfg = Config(alerts={"email": {
        "enabled": True, "from_addr": "lanfence@example.com", "to_addrs": ["me@example.com"],
    }})

    with patch("lanfence.digest.smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value
        instance.starttls.side_effect = ssl.SSLCertVerificationError("certificate verify failed")
        ok = send_digest_email(digest, cfg)
    assert ok is False
    instance.send_message.assert_not_called()


def test_send_digest_email_rejects_plaintext_credentials_when_tls_disabled(tmp_path: Path):
    digest = _digest(tmp_path)
    cfg = Config(alerts={"email": {
        "enabled": True, "from_addr": "lanfence@example.com", "to_addrs": ["me@example.com"],
        "use_tls": False, "username": "operator", "password": "hunter2",
    }})

    with patch("lanfence.digest.smtplib.SMTP") as mock_smtp:
        ok = send_digest_email(digest, cfg)
    assert ok is False
    mock_smtp.assert_not_called()


def test_send_digest_email_failure(tmp_path: Path):
    import smtplib

    digest = _digest(tmp_path)
    cfg = Config(alerts={"email": {
        "enabled": True, "from_addr": "lanfence@example.com", "to_addrs": ["me@example.com"],
    }})

    with patch("lanfence.digest.smtplib.SMTP", side_effect=smtplib.SMTPException("boom")):
        ok = send_digest_email(digest, cfg)
    assert ok is False


def test_send_digest_slack_and_discord_and_teams_and_ntfy_success(tmp_path: Path):
    digest = _digest(tmp_path)
    cfg = Config(alerts={
        "slack": {"enabled": True, "webhook_url": "https://hooks.slack.example/x"},
        "discord": {"enabled": True, "webhook_url": "https://discord.example/x"},
        "teams": {"enabled": True, "webhook_url": "https://teams.example/x"},
        "ntfy": {"enabled": True, "url": "https://ntfy.example/topic"},
    })

    class _FakeResp:
        def read(self):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("lanfence.digest.urllib.request.urlopen", return_value=_FakeResp()):
        assert send_digest_slack(digest, cfg) is True
        assert send_digest_discord(digest, cfg) is True
        assert send_digest_teams(digest, cfg) is True
        assert send_digest_ntfy(digest, cfg) is True


def test_dispatch_digest_continues_after_one_channel_fails(tmp_path: Path):
    digest = _digest(tmp_path)
    cfg = Config(alerts={
        "webhook": {"enabled": True, "url": "https://example.com/hook"},
        "slack": {"enabled": True, "webhook_url": "https://hooks.slack.example/x"},
    })

    def fake_sender(name, ok):
        return lambda d, c: ok

    with patch.dict(
        "lanfence.digest._SENDERS",
        {"webhook": fake_sender("webhook", False), "slack": fake_sender("slack", True)},
    ):
        results = dispatch_digest(digest, cfg, channels=["webhook", "slack"])

    assert results == {"webhook": False, "slack": True}


def test_dispatch_digest_channel_raising_is_reported_as_failure_not_crash(tmp_path: Path):
    digest = _digest(tmp_path)
    cfg = Config()

    def boom(d, c):
        raise RuntimeError("unexpected")

    with patch.dict("lanfence.digest._SENDERS", {"webhook": boom}):
        results = dispatch_digest(digest, cfg, channels=["webhook"])

    assert results == {"webhook": False}


# --- safe error reporting (no server-controlled/sensitive text in logs) ----


_SENTINEL = "SENTINEL_SECRET_DO_NOT_LEAK_hunter2"


def test_send_digest_email_logs_never_contain_a_crafted_smtp_response(tmp_path: Path, caplog):
    import logging
    import smtplib

    digest = _digest(tmp_path)
    cfg = Config(alerts={"email": {
        "enabled": True, "from_addr": "lanfence@example.com", "to_addrs": ["me@example.com"],
    }})
    exc = smtplib.SMTPResponseException(535, f"{_SENTINEL} auth failed".encode())
    with caplog.at_level(logging.ERROR):
        with patch("lanfence.digest.smtplib.SMTP", side_effect=exc):
            ok = send_digest_email(digest, cfg)
    assert ok is False
    assert _SENTINEL not in caplog.text


def test_send_digest_ntfy_logs_never_contain_a_crafted_http_reason(tmp_path: Path, caplog):
    import logging
    import urllib.error

    from lanfence.digest import send_digest_ntfy

    digest = _digest(tmp_path)
    cfg = Config(alerts={"ntfy": {"enabled": True, "url": f"https://ntfy.sh/{_SENTINEL}-topic"}})
    exc = urllib.error.HTTPError(url=cfg.alerts.ntfy.url, code=403, msg=_SENTINEL, hdrs=None, fp=None)
    with caplog.at_level(logging.ERROR):
        with patch("lanfence.digest.urllib.request.urlopen", side_effect=exc):
            ok = send_digest_ntfy(digest, cfg)
    assert ok is False
    assert _SENTINEL not in caplog.text


def test_dispatch_digest_unexpected_exception_logs_never_contain_sentinel(tmp_path: Path, caplog):
    import logging

    digest = _digest(tmp_path)
    cfg = Config()

    def boom(d, c):
        raise RuntimeError(f"{_SENTINEL} unexpected failure")

    with caplog.at_level(logging.ERROR):
        with patch.dict("lanfence.digest._SENDERS", {"webhook": boom}):
            results = dispatch_digest(digest, cfg, channels=["webhook"])
    assert results == {"webhook": False}
    assert _SENTINEL not in caplog.text
