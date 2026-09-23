from __future__ import annotations

import json
import smtplib
from pathlib import Path
from unittest.mock import MagicMock, patch

from lanfence import alerts
from lanfence.config import AlertConfig
from lanfence.models import Finding


def _finding(severity="high", mac="aa:bb:cc:dd:ee:ff", title="Unknown device connected"):
    return Finding(
        mac=mac, title=title, severity=severity,
        rationale="some rationale", recommendation="do something",
        evidence=[f"MAC: {mac}"],
    )


# --- formatting helpers ------------------------------------------------


def test_format_findings_text_includes_heading_and_fields():
    text = alerts._format_findings_text([_finding()], heading="LAN Fence")
    assert "LAN Fence: 1 finding(s)" in text
    assert "[HIGH] Unknown device connected" in text
    assert "MAC: aa:bb:cc:dd:ee:ff" in text
    assert "some rationale" in text
    assert "Recommendation: do something" in text


def test_format_findings_text_lists_full_evidence_not_just_mac():
    finding = Finding(
        mac="aa:bb:cc:dd:ee:ff", title="Always-on device has been absent longer than expected",
        severity="medium", kind="availability", rationale="absent too long",
        recommendation="check it",
        evidence=[
            "MAC: aa:bb:cc:dd:ee:ff", "IP: 10.0.0.5", "Hostname: Galaxy-A33-5G", "Vendor: Samsung",
            "Trusted as: Emily Work Phone", "Owner: Emily", "Location: Home office",
        ],
    )
    text = alerts._format_findings_text([finding], heading="LAN Fence")
    assert "IP: 10.0.0.5" in text
    assert "Hostname: Galaxy-A33-5G" in text
    assert "Vendor: Samsung" in text
    assert "Trusted as: Emily Work Phone" in text
    assert "Owner: Emily" in text
    assert "Location: Home office" in text


def test_format_findings_text_no_heading():
    text = alerts._format_findings_text([_finding()], heading=None)
    assert "LAN Fence:" not in text
    assert "[HIGH]" in text


def test_format_findings_text_handles_finding_with_no_mac():
    finding = Finding(
        mac=None, title="Unexpected DHCP server observed", severity="medium",
        kind="network_service", subject_id="eth0/192.168.1.66",
        evidence=["Interface: eth0", "DHCP server identifier (option 54): 192.168.1.66"],
    )
    text = alerts._format_findings_text([finding], heading="LAN Fence")
    assert "Interface: eth0" in text
    assert "DHCP server identifier (option 54): 192.168.1.66" in text
    assert "MAC: None" not in text
    assert "Subject:" not in text  # no separate Subject line - the evidence bullets already cover it


def test_finding_subject_prefers_mac_then_subject_id_then_placeholder():
    assert alerts._finding_subject(_finding(mac="aa:bb:cc:dd:ee:ff")) == "aa:bb:cc:dd:ee:ff"
    assert alerts._finding_subject(
        Finding(mac=None, title="t", severity="medium", subject_id="eth0/1.2.3.4")
    ) == "eth0/1.2.3.4"
    assert alerts._finding_subject(Finding(mac=None, title="t", severity="medium")) == "[no device]"


def test_format_findings_compact_joins_and_truncates():
    findings = [_finding(title=f"finding {i}") for i in range(20)]
    text = alerts._format_findings_compact(findings, max_len=100)
    assert len(text) == 100
    assert text.endswith("…")


def test_format_findings_compact_no_truncation_when_short():
    text = alerts._format_findings_compact([_finding()], max_len=1000)
    assert "…" not in text
    assert "LAN Fence: 1 finding(s)" in text


# --- findings_to_alert ---------------------------------------------------


def test_findings_to_alert_filters_by_min_severity():
    cfg = AlertConfig(min_severity="medium")
    findings = [_finding("info"), _finding("medium"), _finding("high")]
    assert [f.severity for f in alerts.findings_to_alert(findings, cfg)] == ["medium", "high"]


# --- syslog ----------------------------------------------------------------


def test_send_syslog_calls_syslog_when_enabled():
    cfg = AlertConfig()
    cfg.syslog.enabled = True
    with patch("lanfence.alerts.syslog") as syslog_mock:
        alerts.send_syslog([_finding()], cfg)
    syslog_mock.openlog.assert_called_once()
    syslog_mock.syslog.assert_called_once()
    syslog_mock.closelog.assert_called_once()


def test_send_syslog_noop_when_disabled():
    cfg = AlertConfig()
    with patch("lanfence.alerts.syslog") as syslog_mock:
        alerts.send_syslog([_finding()], cfg)
    syslog_mock.openlog.assert_not_called()


def test_send_syslog_noop_when_no_findings():
    cfg = AlertConfig()
    cfg.syslog.enabled = True
    with patch("lanfence.alerts.syslog") as syslog_mock:
        alerts.send_syslog([], cfg)
    syslog_mock.openlog.assert_not_called()


# --- HTML formatting ----------------------------------------------------


def test_format_findings_html_contains_branding_and_finding():
    html_body = alerts.format_findings_html([_finding()])
    assert "<!doctype html>" in html_body.lower()
    assert "aa:bb:cc:dd:ee:ff" in html_body
    assert "Unknown device connected" in html_body
    assert "some rationale" in html_body
    assert "Recommendation: do something" in html_body
    assert "stablestate.co.uk" in html_body
    assert "MIT License" in html_body
    assert "github.com/rosscooney/lanfence" in html_body
    assert 'src="cid:lanfence-logo"' in html_body


def test_format_findings_html_handles_finding_with_no_mac():
    finding = Finding(
        mac=None, title="Unexpected DHCP server observed", severity="medium",
        kind="network_service", subject_id="eth0/192.168.1.66",
        evidence=["Interface: eth0", "DHCP server identifier (option 54): 192.168.1.66"],
    )
    html_body = alerts.format_findings_html([finding])
    assert "Interface: eth0" in html_body
    assert "DHCP server identifier (option 54): 192.168.1.66" in html_body


def test_format_findings_html_escapes_hostile_finding_data():
    finding = Finding(
        mac="aa:bb:cc:dd:ee:ff", title="<script>alert(1)</script>", severity="high",
        rationale="<img src=x onerror=alert(1)>",
    )
    html_body = alerts.format_findings_html([finding])
    assert "<script>alert(1)</script>" not in html_body
    assert "<img src=x onerror=alert(1)>" not in html_body
    assert "&lt;script&gt;" in html_body


def test_format_findings_html_lists_full_evidence_not_just_mac():
    finding = Finding(
        mac="aa:bb:cc:dd:ee:ff", title="Always-on device has been absent longer than expected",
        severity="medium", kind="availability", rationale="absent too long",
        recommendation="check it",
        evidence=[
            "MAC: aa:bb:cc:dd:ee:ff", "IP: 10.0.0.5", "Hostname: Galaxy-A33-5G", "Vendor: Samsung",
            "Trusted as: Emily Work Phone", "Owner: Emily", "Location: Home office",
        ],
    )
    html_body = alerts.format_findings_html([finding])
    assert "IP: 10.0.0.5" in html_body
    assert "Hostname: Galaxy-A33-5G" in html_body
    assert "Vendor: Samsung" in html_body
    assert "Trusted as: Emily Work Phone" in html_body
    assert "Owner: Emily" in html_body
    assert "Location: Home office" in html_body


def test_format_findings_html_escapes_hostile_evidence_line():
    finding = Finding(
        mac="aa:bb:cc:dd:ee:ff", title="Unknown device connected", severity="high",
        evidence=["Hostname: <script>alert(1)</script>"],
    )
    html_body = alerts.format_findings_html([finding])
    assert "<script>alert(1)</script>" not in html_body
    assert "&lt;script&gt;" in html_body


def test_format_findings_html_omits_evidence_list_when_empty():
    finding = Finding(mac="aa:bb:cc:dd:ee:ff", title="Unknown device connected", severity="high")
    html_body = alerts.format_findings_html([finding])
    assert "<ul" not in html_body


# --- email -------------------------------------------------------------


def test_send_email_sends_when_configured():
    cfg = AlertConfig()
    cfg.email.enabled = True
    cfg.email.from_addr = "lanfence@example.com"
    cfg.email.to_addrs = ["me@example.com"]

    smtp_instance = MagicMock()
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = smtp_instance
    with patch("lanfence.alerts.smtplib.SMTP", return_value=smtp_cm) as smtp_mock:
        alerts.send_email([_finding()], cfg)

    smtp_mock.assert_called_once_with("localhost", 587, timeout=10)
    smtp_instance.starttls.assert_called_once()
    smtp_instance.send_message.assert_called_once()
    sent_msg = smtp_instance.send_message.call_args.args[0]
    assert sent_msg["From"] == "lanfence@example.com"
    assert sent_msg["To"] == "me@example.com"


def test_send_email_is_multipart_with_html_alternative():
    cfg = AlertConfig()
    cfg.email.enabled = True
    cfg.email.from_addr = "lanfence@example.com"
    cfg.email.to_addrs = ["me@example.com"]

    with patch("lanfence.alerts.smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value
        alerts.send_email([_finding()], cfg)
    sent_msg = instance.send_message.call_args.args[0]
    assert sent_msg.is_multipart()
    content_types = {part.get_content_type() for part in sent_msg.walk()}
    assert "text/plain" in content_types
    assert "text/html" in content_types
    html_part = next(part for part in sent_msg.walk() if part.get_content_type() == "text/html")
    assert "Unknown device connected" in html_part.get_content()


def test_send_email_attaches_logo_with_matching_content_id():
    cfg = AlertConfig()
    cfg.email.enabled = True
    cfg.email.from_addr = "lanfence@example.com"
    cfg.email.to_addrs = ["me@example.com"]

    with patch("lanfence.alerts.smtplib.SMTP") as mock_smtp:
        instance = mock_smtp.return_value.__enter__.return_value
        alerts.send_email([_finding()], cfg)
    sent_msg = instance.send_message.call_args.args[0]

    image_parts = [part for part in sent_msg.walk() if part.get_content_type() == "image/png"]
    assert len(image_parts) == 1
    assert image_parts[0].get("Content-ID") == "<lanfence-logo>"
    assert image_parts[0].get("Content-Disposition", "").startswith("inline")
    assert image_parts[0].get_payload(decode=True)[:8] == b"\x89PNG\r\n\x1a\n"

    html_part = next(part for part in sent_msg.walk() if part.get_content_type() == "text/html")
    assert 'src="cid:lanfence-logo"' in html_part.get_content()


def test_send_email_starttls_uses_a_verifying_context():
    """STARTTLS must never fall back to smtplib's own unverified default
    context - see lanfence.smtp_utils.build_smtp_context."""

    import ssl

    cfg = AlertConfig()
    cfg.email.enabled = True
    cfg.email.from_addr = "lanfence@example.com"
    cfg.email.to_addrs = ["me@example.com"]

    smtp_instance = MagicMock()
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = smtp_instance
    with patch("lanfence.alerts.smtplib.SMTP", return_value=smtp_cm):
        alerts.send_email([_finding()], cfg)

    smtp_instance.starttls.assert_called_once()
    context = smtp_instance.starttls.call_args.kwargs.get("context")
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_send_email_certificate_failure_prevents_delivery():
    """A STARTTLS certificate verification failure must abort delivery
    (never fall through to send_message with an unverified/plaintext
    connection) and must not raise out of send_email."""

    import ssl

    cfg = AlertConfig()
    cfg.email.enabled = True
    cfg.email.from_addr = "lanfence@example.com"
    cfg.email.to_addrs = ["me@example.com"]

    smtp_instance = MagicMock()
    smtp_instance.starttls.side_effect = ssl.SSLCertVerificationError("certificate verify failed")
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = smtp_instance
    with patch("lanfence.alerts.smtplib.SMTP", return_value=smtp_cm):
        alerts.send_email([_finding()], cfg)  # must not raise

    smtp_instance.send_message.assert_not_called()


def test_send_email_rejects_plaintext_credentials_when_tls_disabled():
    """Username/password must never be sent when use_tls is disabled -
    see lanfence.smtp_utils.SmtpAuthWithoutTlsError."""

    cfg = AlertConfig()
    cfg.email.enabled = True
    cfg.email.from_addr = "lanfence@example.com"
    cfg.email.to_addrs = ["me@example.com"]
    cfg.email.use_tls = False
    cfg.email.username = "operator"
    cfg.email.password = "hunter2"

    with patch("lanfence.alerts.smtplib.SMTP") as smtp_mock:
        alerts.send_email([_finding()], cfg)  # must not raise

    smtp_mock.assert_not_called()


def test_send_email_allows_unauthenticated_local_relay_without_tls():
    """An explicitly configured unauthenticated relay (no username/password)
    with use_tls disabled must still be allowed - only the credential+
    plaintext combination is refused."""

    cfg = AlertConfig()
    cfg.email.enabled = True
    cfg.email.from_addr = "lanfence@example.com"
    cfg.email.to_addrs = ["me@example.com"]
    cfg.email.use_tls = False

    smtp_instance = MagicMock()
    smtp_cm = MagicMock()
    smtp_cm.__enter__.return_value = smtp_instance
    with patch("lanfence.alerts.smtplib.SMTP", return_value=smtp_cm):
        alerts.send_email([_finding()], cfg)

    smtp_instance.starttls.assert_not_called()
    smtp_instance.login.assert_not_called()
    smtp_instance.send_message.assert_called_once()


def test_send_email_skips_when_missing_addrs():
    cfg = AlertConfig()
    cfg.email.enabled = True
    with patch("lanfence.alerts.smtplib.SMTP") as smtp_mock:
        alerts.send_email([_finding()], cfg)
    smtp_mock.assert_not_called()


def test_send_email_handles_smtp_failure_without_raising():
    cfg = AlertConfig()
    cfg.email.enabled = True
    cfg.email.from_addr = "a@example.com"
    cfg.email.to_addrs = ["b@example.com"]
    with patch("lanfence.alerts.smtplib.SMTP", side_effect=OSError("connection refused")):
        alerts.send_email([_finding()], cfg)  # must not raise


# --- generic JSON-webhook-shaped channels (webhook/slack/discord/teams) ----


class _FakeResponse:
    def read(self):
        return b""

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def test_send_webhook_posts_findings_json():
    cfg = AlertConfig()
    cfg.webhook.enabled = True
    cfg.webhook.url = "https://example.com/hook"
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_webhook([_finding()], cfg)
    request = urlopen_mock.call_args.args[0]
    assert request.full_url == "https://example.com/hook"
    body = json.loads(request.data)
    assert body["findings"][0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_send_slack_posts_text_payload():
    cfg = AlertConfig()
    cfg.slack.enabled = True
    cfg.slack.webhook_url = "https://hooks.slack.com/services/xyz"
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_slack([_finding()], cfg)
    request = urlopen_mock.call_args.args[0]
    body = json.loads(request.data)
    assert "LAN Fence: 1 finding(s)" in body["text"]


def test_send_slack_skips_without_webhook_url():
    cfg = AlertConfig()
    cfg.slack.enabled = True
    with patch("lanfence.alerts.urllib.request.urlopen") as urlopen_mock:
        alerts.send_slack([_finding()], cfg)
    urlopen_mock.assert_not_called()


def test_send_discord_posts_content_payload_and_truncates():
    cfg = AlertConfig()
    cfg.discord.enabled = True
    cfg.discord.webhook_url = "https://discord.com/api/webhooks/xyz"
    findings = [_finding(title=f"finding number {i}") for i in range(200)]
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_discord(findings, cfg)
    request = urlopen_mock.call_args.args[0]
    body = json.loads(request.data)
    assert len(body["content"]) <= 2000
    assert body["content"].endswith("(truncated)")


def test_send_teams_posts_messagecard_payload():
    cfg = AlertConfig()
    cfg.teams.enabled = True
    cfg.teams.webhook_url = "https://example.webhook.office.com/xyz"
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_teams([_finding()], cfg)
    request = urlopen_mock.call_args.args[0]
    body = json.loads(request.data)
    assert body["@type"] == "MessageCard"
    assert "LAN Fence: 1 finding(s)" in body["summary"]


def test_json_channels_swallow_network_errors():
    cfg = AlertConfig()
    cfg.webhook.enabled = True
    cfg.webhook.url = "https://example.com/hook"
    with patch("lanfence.alerts.urllib.request.urlopen", side_effect=OSError("nope")):
        alerts.send_webhook([_finding()], cfg)  # must not raise


# --- ntfy --------------------------------------------------------------


def test_send_ntfy_posts_plain_text_with_title_header():
    cfg = AlertConfig()
    cfg.ntfy.enabled = True
    cfg.ntfy.url = "https://ntfy.sh/my-lanfence-topic"
    cfg.ntfy.priority = "high"
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_ntfy([_finding()], cfg)
    request = urlopen_mock.call_args.args[0]
    assert request.full_url == "https://ntfy.sh/my-lanfence-topic"
    assert request.get_header("Title") == "LAN Fence: 1 finding(s)"
    assert request.get_header("Priority") == "high"
    assert b"Unknown device connected" in request.data


def test_send_ntfy_skips_without_url():
    cfg = AlertConfig()
    cfg.ntfy.enabled = True
    with patch("lanfence.alerts.urllib.request.urlopen") as urlopen_mock:
        alerts.send_ntfy([_finding()], cfg)
    urlopen_mock.assert_not_called()


# --- twilio --------------------------------------------------------------


def _configured_twilio_config():
    cfg = AlertConfig()
    cfg.twilio.enabled = True
    cfg.twilio.account_sid = "ACxxxx"
    cfg.twilio.auth_token = "secret"
    cfg.twilio.from_number = "+15550001111"
    cfg.twilio.to_numbers = ["+15550002222", "+15550003333"]
    return cfg


def test_send_twilio_posts_one_message_per_recipient():
    cfg = _configured_twilio_config()
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_twilio([_finding()], cfg)
    assert urlopen_mock.call_count == 2
    urls = {call.args[0].full_url for call in urlopen_mock.call_args_list}
    assert urls == {"https://api.twilio.com/2010-04-01/Accounts/ACxxxx/Messages.json"}


def test_send_twilio_uses_basic_auth_and_form_body():
    cfg = _configured_twilio_config()
    cfg.twilio.to_numbers = ["+15550002222"]
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_twilio([_finding()], cfg)
    request = urlopen_mock.call_args.args[0]
    assert request.get_header("Authorization").startswith("Basic ")
    from urllib.parse import parse_qs

    body = parse_qs(request.data.decode())
    assert body["From"] == ["+15550001111"]
    assert body["To"] == ["+15550002222"]
    assert "LAN Fence" in body["Body"][0]


def test_send_twilio_caps_body_length():
    cfg = _configured_twilio_config()
    cfg.twilio.to_numbers = ["+15550002222"]
    findings = [_finding(title=f"a very long finding title number {i}") for i in range(50)]
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_twilio(findings, cfg)
    from urllib.parse import parse_qs

    body = parse_qs(urlopen_mock.call_args.args[0].data.decode())
    assert len(body["Body"][0]) <= alerts._TWILIO_MAX_BODY_LEN


def test_send_twilio_skips_when_not_fully_configured():
    cfg = AlertConfig()
    cfg.twilio.enabled = True
    cfg.twilio.account_sid = "ACxxxx"
    # missing auth_token/from_number/to_numbers
    with patch("lanfence.alerts.urllib.request.urlopen") as urlopen_mock:
        alerts.send_twilio([_finding()], cfg)
    urlopen_mock.assert_not_called()


def test_send_twilio_one_recipient_failure_does_not_stop_others():
    cfg = _configured_twilio_config()
    with patch("lanfence.alerts.urllib.request.urlopen", side_effect=[OSError("boom"), _FakeResponse()]) as urlopen_mock:
        alerts.send_twilio([_finding()], cfg)  # must not raise
    assert urlopen_mock.call_count == 2


def test_sms_segment_count():
    assert alerts._sms_segment_count("x" * 10) == 1
    assert alerts._sms_segment_count("x" * 153) == 1
    assert alerts._sms_segment_count("x" * 154) == 2
    assert alerts._sms_segment_count("x" * 480) == 4


def test_send_twilio_without_store_is_unbudgeted():
    """Backward compatible: a caller with no DeviceStore handy (store=None,
    the default) gets the pre-existing unbudgeted behavior."""

    cfg = _configured_twilio_config()
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_twilio([_finding()], cfg)
    assert urlopen_mock.call_count == 2


def test_send_twilio_enforces_daily_segment_budget(tmp_path: Path):
    from lanfence.db import DeviceStore

    cfg = _configured_twilio_config()
    cfg.twilio.max_segments_per_day = 1  # exactly one recipient's worth (a short message is 1 segment)
    store = DeviceStore(tmp_path / "db.sqlite")
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_twilio([_finding()], cfg, store=store)
    store.close()
    # Two recipients configured, but only enough budget for one.
    assert urlopen_mock.call_count == 1


def test_send_twilio_budget_persists_across_calls(tmp_path: Path):
    from lanfence.db import DeviceStore

    cfg = _configured_twilio_config()
    cfg.twilio.to_numbers = ["+15550002222"]
    cfg.twilio.max_segments_per_day = 1
    db_path = tmp_path / "db.sqlite"

    store = DeviceStore(db_path)
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_twilio([_finding()], cfg, store=store)  # consumes the whole budget
        alerts.send_twilio([_finding()], cfg, store=store)  # budget already exhausted
    store.close()
    assert urlopen_mock.call_count == 1


def test_send_twilio_budget_zero_is_unlimited(tmp_path: Path):
    from lanfence.db import DeviceStore

    cfg = _configured_twilio_config()
    cfg.twilio.max_segments_per_day = 0
    store = DeviceStore(tmp_path / "db.sqlite")
    with patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeResponse()) as urlopen_mock:
        alerts.send_twilio([_finding()], cfg, store=store)
    store.close()
    assert urlopen_mock.call_count == 2


# --- dispatch ------------------------------------------------------------


def test_dispatch_calls_every_channel_with_filtered_findings():
    cfg = AlertConfig(min_severity="high")
    findings = [_finding("info"), _finding("high")]
    channel_names = ["send_syslog", "send_email", "send_webhook", "send_slack",
                      "send_discord", "send_teams", "send_ntfy", "send_twilio"]
    with patch.multiple("lanfence.alerts", **{name: MagicMock() for name in channel_names}):
        sent = alerts.dispatch(findings, cfg)
        for name in channel_names:
            getattr(alerts, name).assert_called_once()
            called_findings = getattr(alerts, name).call_args.args[0]
            assert [f.severity for f in called_findings] == ["high"]
    assert [f.severity for f in sent] == ["high"]


def test_dispatch_returns_empty_and_calls_nothing_when_below_threshold():
    cfg = AlertConfig(min_severity="high")
    with patch("lanfence.alerts.send_syslog") as syslog_mock:
        sent = alerts.dispatch([_finding("info")], cfg)
    assert sent == []
    syslog_mock.assert_not_called()


def test_dispatch_threads_store_through_to_send_twilio_only():
    """`store` is only meaningful to send_twilio (Twilio's SMS budget) -
    every other channel here is pure network I/O with no database access,
    which is what lets a background delivery worker call this safely."""

    cfg = AlertConfig(min_severity="high")
    sentinel_store = object()
    with patch("lanfence.alerts.send_twilio") as twilio_mock:
        alerts.dispatch([_finding("high")], cfg, store=sentinel_store)
    assert twilio_mock.call_args.kwargs.get("store") is sentinel_store


# --- safe error reporting (no server-controlled/sensitive text in logs) ----


_SENTINEL = "SENTINEL_SECRET_DO_NOT_LEAK_hunter2"


def test_send_webhook_logs_never_contain_a_crafted_http_reason(caplog):
    import logging
    import urllib.error

    cfg = AlertConfig()
    cfg.webhook.enabled = True
    cfg.webhook.url = f"https://user:{_SENTINEL}@evil.example.com/hook"
    exc = urllib.error.HTTPError(url=cfg.webhook.url, code=500, msg=_SENTINEL, hdrs=None, fp=None)
    with caplog.at_level(logging.ERROR):
        with patch("lanfence.alerts.urllib.request.urlopen", side_effect=exc):
            alerts.send_webhook([_finding()], cfg)
    assert _SENTINEL not in caplog.text
    assert "evil.example.com" not in caplog.text


def test_send_email_logs_never_contain_a_crafted_smtp_response(caplog):
    import logging

    cfg = AlertConfig()
    cfg.email.enabled = True
    cfg.email.from_addr = "a@example.com"
    cfg.email.to_addrs = ["b@example.com"]
    exc = smtplib.SMTPResponseException(535, f"{_SENTINEL} auth failed".encode())
    with caplog.at_level(logging.ERROR):
        with patch("lanfence.alerts.smtplib.SMTP", side_effect=exc):
            alerts.send_email([_finding()], cfg)
    assert _SENTINEL not in caplog.text


def test_send_twilio_logs_never_contain_the_recipient_number(caplog):
    import logging
    import urllib.error

    cfg = _configured_twilio_config()
    secret_number = "+15559998888"
    cfg.twilio.to_numbers = [secret_number]
    exc = urllib.error.HTTPError(url="https://api.twilio.com/x", code=400, msg=_SENTINEL, hdrs=None, fp=None)
    with caplog.at_level(logging.ERROR):
        with patch("lanfence.alerts.urllib.request.urlopen", side_effect=exc):
            alerts.send_twilio([_finding()], cfg)
    assert secret_number not in caplog.text
    assert _SENTINEL not in caplog.text


def test_send_ntfy_logs_never_contain_a_crafted_http_reason(caplog):
    import logging
    import urllib.error

    cfg = AlertConfig()
    cfg.ntfy.enabled = True
    cfg.ntfy.url = f"https://ntfy.sh/{_SENTINEL}-topic"
    exc = urllib.error.HTTPError(url=cfg.ntfy.url, code=403, msg=_SENTINEL, hdrs=None, fp=None)
    with caplog.at_level(logging.ERROR):
        with patch("lanfence.alerts.urllib.request.urlopen", side_effect=exc):
            alerts.send_ntfy([_finding()], cfg)
    assert _SENTINEL not in caplog.text
