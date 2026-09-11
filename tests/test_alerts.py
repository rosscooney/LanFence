from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from lanfence import alerts
from lanfence.config import AlertConfig
from lanfence.models import Finding


def _finding(severity="high", mac="aa:bb:cc:dd:ee:ff", title="Unknown device connected"):
    return Finding(
        mac=mac, title=title, severity=severity,
        rationale="some rationale", recommendation="do something",
    )


# --- formatting helpers ------------------------------------------------


def test_format_findings_text_includes_heading_and_fields():
    text = alerts._format_findings_text([_finding()], heading="LAN Fence")
    assert "LAN Fence: 1 finding(s)" in text
    assert "[HIGH] Unknown device connected" in text
    assert "MAC: aa:bb:cc:dd:ee:ff" in text
    assert "some rationale" in text
    assert "Recommendation: do something" in text


def test_format_findings_text_no_heading():
    text = alerts._format_findings_text([_finding()], heading=None)
    assert "LAN Fence:" not in text
    assert "[HIGH]" in text


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
