from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from lanfence.channels import (
    CHANNEL_NAMES,
    CLEAR,
    KEEP,
    ConcurrentModificationError,
    ConfigFileError,
    apply_channel_values,
    apply_digest_selection,
    channel_summary,
    check_insecure_permissions,
    digest_selected,
    is_channel_configured,
    list_channel_statuses,
    load_channels_config_file,
    resolve_channels_config_path,
    save_channels_config_file,
    send_channel_test_message,
    set_channel_enabled,
    supports_digest,
    validate_channel_values,
)
from lanfence.config import Config


# --- is_channel_configured / channel_summary -------------------------------


def test_all_channel_names_covered_by_is_configured_and_summary():
    cfg = Config()
    for channel in CHANNEL_NAMES:
        assert isinstance(is_channel_configured(channel, cfg), bool)
        assert isinstance(channel_summary(channel, cfg), str)


def test_slack_incomplete_by_default():
    cfg = Config()
    assert is_channel_configured("slack", cfg) is False
    assert channel_summary("slack", cfg) == "not configured"


def test_slack_configured_shows_hostname_only_never_full_url():
    cfg = Config(alerts={"slack": {"webhook_url": "https://hooks.slack.com/services/T000/B000/xxxxSECRETxxxx"}})
    assert is_channel_configured("slack", cfg) is True
    summary = channel_summary("slack", cfg)
    assert summary == "hooks.slack.com"
    assert "xxxxSECRETxxxx" not in summary
    assert "T000" not in summary


def test_webhook_summary_hostname_only():
    cfg = Config(alerts={"webhook": {"url": "https://example.com/hooks/abcsecrettoken?key=shh"}})
    assert channel_summary("webhook", cfg) == "example.com"


def test_email_summary_masks_single_recipient():
    cfg = Config(alerts={"email": {"from_addr": "lanfence@example.com", "to_addrs": ["alice@example.com"]}})
    assert is_channel_configured("email", cfg) is True
    summary = channel_summary("email", cfg)
    assert "alice@example.com" not in summary
    assert summary.endswith("@example.com")


def test_email_summary_shows_count_for_multiple_recipients():
    cfg = Config(alerts={"email": {
        "from_addr": "lanfence@example.com",
        "to_addrs": ["alice@example.com", "bob@example.com"],
    }})
    assert channel_summary("email", cfg) == "2 recipients"


def test_email_incomplete_without_from_or_to():
    cfg = Config(alerts={"email": {"to_addrs": ["alice@example.com"]}})
    assert is_channel_configured("email", cfg) is False


def test_twilio_summary_masks_numbers():
    cfg = Config(alerts={"twilio": {
        "account_sid": "AC123", "auth_token": "secrettoken", "from_number": "+15551234567",
        "to_numbers": ["+15559876543"],
    }})
    assert is_channel_configured("twilio", cfg) is True
    summary = channel_summary("twilio", cfg)
    assert "+15559876543" not in summary
    assert "secrettoken" not in summary
    assert summary.startswith("+1") and summary.endswith("43")


def test_twilio_incomplete_missing_auth_token():
    cfg = Config(alerts={"twilio": {"account_sid": "AC123", "from_number": "+15551234567",
                                     "to_numbers": ["+15559876543"]}})
    assert is_channel_configured("twilio", cfg) is False


def test_syslog_always_configured_via_defaults():
    cfg = Config()
    assert is_channel_configured("syslog", cfg) is True
    assert channel_summary("syslog", cfg) == "/dev/log"


def test_ntfy_summary_hostname_only():
    cfg = Config(alerts={"ntfy": {"url": "https://ntfy.sh/my-secret-topic-name"}})
    summary = channel_summary("ntfy", cfg)
    assert summary == "ntfy.sh"
    assert "my-secret-topic-name" not in summary


def test_digest_support_flags():
    assert supports_digest("slack") is True
    assert supports_digest("twilio") is False
    assert supports_digest("syslog") is False


def test_digest_selected_reflects_config():
    cfg = Config(digest={"channels": ["slack"]})
    assert digest_selected("slack", cfg) is True
    assert digest_selected("email", cfg) is False


def test_list_channel_statuses_covers_every_channel_and_no_secrets_leak():
    cfg = Config(alerts={
        "slack": {"webhook_url": "https://hooks.slack.com/services/SECRET"},
        "twilio": {"account_sid": "AC1", "auth_token": "tok", "from_number": "+15551234567",
                   "to_numbers": ["+15559876543"]},
    })
    statuses = list_channel_statuses(cfg)
    assert {s.channel for s in statuses} == set(CHANNEL_NAMES)
    for s in statuses:
        assert "SECRET" not in s.summary
        assert "tok" not in s.summary


def test_list_channel_statuses_digest_none_for_unsupported_channel():
    cfg = Config()
    statuses = {s.channel: s for s in list_channel_statuses(cfg)}
    assert statuses["twilio"].digest_selected is None
    assert statuses["syslog"].digest_selected is None
    assert statuses["slack"].digest_selected is False


# --- validate_channel_values -------------------------------------------------


def test_validate_slack_rejects_non_http_scheme():
    errors = validate_channel_values("slack", {"webhook_url": "ftp://example.com/x"})
    assert any("http" in e for e in errors)


def test_validate_slack_rejects_missing_hostname():
    errors = validate_channel_values("slack", {"webhook_url": "https:///no-host"})
    assert errors


def test_validate_slack_accepts_valid_url():
    assert validate_channel_values("slack", {"webhook_url": "https://hooks.slack.com/services/x"}) == []


def test_validate_allows_plain_http_url():
    """Local HTTP webhook/ntfy endpoints are explicitly supported - not
    forced to https."""

    assert validate_channel_values("webhook", {"url": "http://192.168.1.50:8080/hook"}) == []


def test_validate_timeout_must_be_finite_positive():
    assert validate_channel_values("slack", {"timeout_seconds": -1}) != []
    assert validate_channel_values("slack", {"timeout_seconds": 0}) != []
    assert validate_channel_values("slack", {"timeout_seconds": float("inf")}) != []
    assert validate_channel_values("slack", {"timeout_seconds": 5.0}) == []


def test_validate_email_port_range():
    base = {"smtp_host": "smtp.example.com", "from_addr": "a@example.com", "to_addrs": ["b@example.com"]}
    assert validate_channel_values("email", {**base, "smtp_port": 0}) != []
    assert validate_channel_values("email", {**base, "smtp_port": 70000}) != []
    assert validate_channel_values("email", {**base, "smtp_port": 587}) == []


def test_validate_email_rejects_invalid_addresses():
    errors = validate_channel_values("email", {
        "from_addr": "not-an-email", "to_addrs": ["also-not-an-email"], "smtp_host": "h", "smtp_port": 587,
    })
    assert len(errors) >= 2


def test_validate_twilio_rejects_non_e164():
    errors = validate_channel_values("twilio", {"from_number": "555-1234", "to_numbers": ["+15551234567"]})
    assert any("E.164" in e or "phone" in e.lower() for e in errors)


def test_validate_twilio_accepts_e164():
    assert validate_channel_values(
        "twilio", {"from_number": "+15551234567", "to_numbers": ["+15559876543"]}
    ) == []


def test_validate_ntfy_priority_choice():
    assert validate_channel_values("ntfy", {"priority": "urgent"}) == []
    assert validate_channel_values("ntfy", {"priority": "screaming"}) != []


def test_validate_syslog_facility_choice():
    assert validate_channel_values("syslog", {"facility": "local0"}) == []
    assert validate_channel_values("syslog", {"facility": "bogus"}) != []


def test_validate_enabling_requires_all_required_fields():
    errors = validate_channel_values("slack", {"enabled": True})
    assert any("cannot enable" in e for e in errors)


def test_validate_enabling_with_complete_fields_passes():
    errors = validate_channel_values("slack", {"webhook_url": "https://hooks.slack.com/x", "enabled": True})
    assert errors == []


def test_validate_not_enabling_allows_incomplete_fields():
    """You can save a partially-filled, disabled channel - only *enabling*
    demands completeness."""

    assert validate_channel_values("slack", {"enabled": False}) == []


# --- apply_channel_values: keep/clear/set, preserving everything else ------


def test_apply_channel_values_sets_new_fields():
    raw = {"scan": {"passive": False}}
    updated = apply_channel_values(raw, "slack", {"webhook_url": "https://x", "enabled": True})
    assert updated["alerts"]["slack"] == {"webhook_url": "https://x", "enabled": True}
    assert updated["scan"] == {"passive": False}  # untouched
    assert raw == {"scan": {"passive": False}}  # original not mutated


def test_apply_channel_values_keep_sentinel_never_touches_existing_secret():
    raw = {"alerts": {"slack": {"webhook_url": "https://existing-secret", "enabled": True}}}
    updated = apply_channel_values(raw, "slack", {"webhook_url": KEEP, "timeout_seconds": 10.0})
    assert updated["alerts"]["slack"]["webhook_url"] == "https://existing-secret"
    assert updated["alerts"]["slack"]["timeout_seconds"] == 10.0


def test_apply_channel_values_clear_sentinel_sets_none():
    raw = {"alerts": {"email": {"password": "hunter2"}}}
    updated = apply_channel_values(raw, "email", {"password": CLEAR})
    assert updated["alerts"]["email"]["password"] is None


def test_apply_channel_values_preserves_other_channels():
    raw = {"alerts": {"discord": {"webhook_url": "https://discord.example", "enabled": True}}}
    updated = apply_channel_values(raw, "slack", {"webhook_url": "https://slack.example"})
    assert updated["alerts"]["discord"] == {"webhook_url": "https://discord.example", "enabled": True}
    assert updated["alerts"]["slack"]["webhook_url"] == "https://slack.example"


def test_apply_channel_values_preserves_unknown_extension_data_within_channel():
    # Even a field this wizard doesn't touch on this call stays put.
    raw = {"alerts": {"slack": {"webhook_url": "https://x", "timeout_seconds": 9.0, "enabled": False}}}
    updated = apply_channel_values(raw, "slack", {"enabled": True})
    assert updated["alerts"]["slack"]["webhook_url"] == "https://x"
    assert updated["alerts"]["slack"]["timeout_seconds"] == 9.0
    assert updated["alerts"]["slack"]["enabled"] is True


def test_apply_digest_selection_add_and_remove():
    raw = {"digest": {"channels": []}}
    added = apply_digest_selection(raw, "slack", selected=True)
    assert added["digest"]["channels"] == ["slack"]
    removed = apply_digest_selection(added, "slack", selected=False)
    assert removed["digest"]["channels"] == []


def test_apply_digest_selection_preserves_other_channels():
    raw = {"digest": {"channels": ["email"]}}
    updated = apply_digest_selection(raw, "slack", selected=True)
    assert set(updated["digest"]["channels"]) == {"email", "slack"}


def test_set_channel_enabled_preserves_other_fields():
    raw = {"alerts": {"slack": {"webhook_url": "https://x", "enabled": False}}}
    updated = set_channel_enabled(raw, "slack", enabled=True)
    assert updated["alerts"]["slack"] == {"webhook_url": "https://x", "enabled": True}


def test_set_channel_enabled_disable_preserves_secret():
    raw = {"alerts": {"twilio": {"account_sid": "AC1", "auth_token": "tok", "enabled": True}}}
    updated = set_channel_enabled(raw, "twilio", enabled=False)
    assert updated["alerts"]["twilio"]["auth_token"] == "tok"
    assert updated["alerts"]["twilio"]["enabled"] is False


# --- config file resolution / load / save -----------------------------------


def test_resolve_channels_config_path_uses_default_when_none():
    from lanfence.channels import DEFAULT_CONFIG_PATH

    assert resolve_channels_config_path(None) == DEFAULT_CONFIG_PATH.expanduser()


def test_resolve_channels_config_path_uses_given_path():
    assert resolve_channels_config_path(Path("/tmp/custom.yaml")) == Path("/tmp/custom.yaml")


def test_resolve_channels_config_path_uses_sudo_user_home_when_run_as_root_via_sudo(monkeypatch):
    """Regression test: sudo lanfence channels/setup and a plain,
    unprivileged invocation must resolve the *same* default config file -
    otherwise one silently reads/writes a completely different file (this
    was previously only fixed for db_path/allowlist_file, not this path)."""

    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "alice")
    monkeypatch.setattr("pwd.getpwnam", lambda name: type("_pw", (), {"pw_dir": "/home/alice"})())
    assert resolve_channels_config_path(None) == Path("/home/alice/.config/lanfence/config.yaml")


def test_resolve_channels_config_path_not_root_ignores_sudo_user(monkeypatch):
    monkeypatch.setattr("lanfence.config.os.geteuid", lambda: 1000)
    monkeypatch.setenv("SUDO_USER", "alice")
    from lanfence.channels import DEFAULT_CONFIG_PATH

    assert resolve_channels_config_path(None) == DEFAULT_CONFIG_PATH.expanduser()


def test_load_missing_file_reports_not_existed(tmp_path: Path):
    loaded = load_channels_config_file(tmp_path / "nonexistent.yaml")
    assert loaded.existed is False
    assert loaded.raw == {}
    assert loaded.raw_bytes is None


def test_load_existing_valid_file(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: true\n")
    loaded = load_channels_config_file(path)
    assert loaded.existed is True
    assert loaded.cfg.alerts.slack.webhook_url == "https://hooks.slack.com/x"


def test_load_malformed_yaml_raises_without_reading_content_into_error(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("alerts: [unterminated\n  secret_value_should_not_appear: xyz123secret")
    with pytest.raises(ConfigFileError) as exc_info:
        load_channels_config_file(path)
    assert "xyz123secret" not in str(exc_info.value)


def test_load_yaml_that_fails_schema_validation_raises(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("alerts:\n  slack:\n    unknown_field_xyz: true\n")
    with pytest.raises(ConfigFileError):
        load_channels_config_file(path)


def test_load_non_mapping_yaml_raises(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigFileError):
        load_channels_config_file(path)


def test_save_writes_atomically_with_owner_only_permissions(tmp_path: Path):
    path = tmp_path / "config.yaml"
    loaded = load_channels_config_file(path)
    updated = apply_channel_values(loaded.raw, "slack", {"webhook_url": "https://hooks.slack.com/x", "enabled": True})
    save_channels_config_file(loaded, updated)

    assert path.is_file()
    import stat

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
    reloaded = load_channels_config_file(path)
    assert reloaded.cfg.alerts.slack.webhook_url == "https://hooks.slack.com/x"


def test_save_detects_concurrent_modification(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("alerts:\n  slack:\n    webhook_url: https://original\n")
    loaded = load_channels_config_file(path)

    # Someone else (or another lanfence invocation) edits the file in the meantime.
    path.write_text("alerts:\n  slack:\n    webhook_url: https://changed-by-someone-else\n")

    updated = apply_channel_values(loaded.raw, "discord", {"webhook_url": "https://discord.example"})
    with pytest.raises(ConcurrentModificationError):
        save_channels_config_file(loaded, updated)

    # And the concurrent edit must survive untouched.
    assert "changed-by-someone-else" in path.read_text()


def test_save_rejects_invalid_merged_config_without_writing(tmp_path: Path):
    path = tmp_path / "config.yaml"
    loaded = load_channels_config_file(path)
    bad_raw = {"alerts": {"slack": {"enabled": "not-a-bool-and-not-coercible-either"}}}
    with pytest.raises(ConfigFileError):
        save_channels_config_file(loaded, bad_raw)
    assert not path.is_file()  # never created


def test_save_preserves_unrelated_sections(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "scan:\n  passive: false\n  interface: eth0\n"
        "dhcp_servers:\n  enabled: true\n"
        "alerts:\n  discord:\n    webhook_url: https://discord.example\n    enabled: true\n"
    )
    loaded = load_channels_config_file(path)
    updated = apply_channel_values(loaded.raw, "slack", {"webhook_url": "https://hooks.slack.com/x", "enabled": True})
    save_channels_config_file(loaded, updated)

    reloaded = load_channels_config_file(path)
    assert reloaded.cfg.scan.passive is False
    assert reloaded.cfg.scan.interface == "eth0"
    assert reloaded.cfg.dhcp_servers.enabled is True
    assert reloaded.cfg.alerts.discord.webhook_url == "https://discord.example"
    assert reloaded.cfg.alerts.slack.webhook_url == "https://hooks.slack.com/x"


def test_check_insecure_permissions_detects_world_readable(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("alerts: {}\n")
    path.chmod(0o644)
    assert check_insecure_permissions(path) == 0o644


def test_check_insecure_permissions_none_for_owner_only(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("alerts: {}\n")
    path.chmod(0o600)
    assert check_insecure_permissions(path) is None


def test_check_insecure_permissions_none_for_missing_file(tmp_path: Path):
    assert check_insecure_permissions(tmp_path / "missing.yaml") is None


# --- send_channel_test_message: honest success/failure, no side effects ----


def test_test_message_refuses_when_disabled():
    cfg = Config(alerts={"slack": {"webhook_url": "https://hooks.slack.com/x", "enabled": False}})
    ok, message = send_channel_test_message("slack", cfg)
    assert ok is False
    assert "disabled" in message
    assert "lanfence setup slack" in message


def test_test_message_slack_success(monkeypatch):
    cfg = Config(alerts={"slack": {"webhook_url": "https://hooks.slack.com/x", "enabled": True}})

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    with patch("lanfence.channels.urllib.request.urlopen", return_value=_Resp()):
        ok, message = send_channel_test_message("slack", cfg)
    assert ok is True
    assert "Slack" in message


def test_test_message_never_reports_success_on_swallowed_exception():
    cfg = Config(alerts={"slack": {"webhook_url": "https://hooks.slack.com/x", "enabled": True}})
    with patch("lanfence.channels.urllib.request.urlopen", side_effect=OSError("boom")):
        ok, message = send_channel_test_message("slack", cfg)
    assert ok is False
    assert "boom" in message or "rejected" in message


def test_test_message_email_uses_smtplib(monkeypatch):
    cfg = Config(alerts={"email": {
        "from_addr": "lanfence@example.com", "to_addrs": ["ops@example.com"], "enabled": True,
    }})
    sent = {}

    class _FakeSMTP:
        def __init__(self, host, port, timeout=10):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            sent["starttls_context"] = context

        def login(self, u, p):
            pass

        def send_message(self, msg):
            sent["subject"] = msg["Subject"]

    with patch("lanfence.channels.smtplib.SMTP", _FakeSMTP):
        ok, message = send_channel_test_message("email", cfg)
    assert ok is True
    assert sent["subject"] == "LAN Fence test message"

    import ssl

    context = sent["starttls_context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_test_message_email_failure_reported_honestly():
    import smtplib

    cfg = Config(alerts={"email": {
        "from_addr": "lanfence@example.com", "to_addrs": ["ops@example.com"], "enabled": True,
    }})
    with patch("lanfence.channels.smtplib.SMTP", side_effect=smtplib.SMTPConnectError(421, "no")):
        ok, message = send_channel_test_message("email", cfg)
    assert ok is False


def test_test_message_syslog(monkeypatch):
    cfg = Config(alerts={"syslog": {"enabled": True}})
    calls = []
    monkeypatch.setattr("lanfence.channels.syslog.openlog", lambda **kw: calls.append(("open", kw)))
    monkeypatch.setattr("lanfence.channels.syslog.syslog", lambda *a: calls.append(("syslog", a)))
    monkeypatch.setattr("lanfence.channels.syslog.closelog", lambda: calls.append(("close",)))
    ok, message = send_channel_test_message("syslog", cfg)
    assert ok is True
    assert any(c[0] == "syslog" for c in calls)


def test_test_message_twilio_sends_to_all_numbers():
    cfg = Config(alerts={"twilio": {
        "account_sid": "AC1", "auth_token": "tok", "from_number": "+15551234567",
        "to_numbers": ["+15559876543", "+15551112222"], "enabled": True,
    }})

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    with patch("lanfence.channels.urllib.request.urlopen", return_value=_Resp()) as mock_open:
        ok, message = send_channel_test_message("twilio", cfg)
    assert ok is True
    assert mock_open.call_count == 2
    assert "2 recipient" in message


def test_test_message_credentials_never_appear_in_returned_message():
    cfg = Config(alerts={"slack": {"webhook_url": "https://hooks.slack.com/services/SUPERSECRET", "enabled": True}})
    with patch("lanfence.channels.urllib.request.urlopen", side_effect=OSError("SUPERSECRET leaked in error?")):
        ok, message = send_channel_test_message("slack", cfg)
    # the exception text itself is safe here (we crafted it), but the
    # *webhook URL* must never be interpolated into the message regardless.
    assert "hooks.slack.com/services/SUPERSECRET" not in message


def test_unknown_channel_test_message_fails_gracefully():
    cfg = Config()
    ok, message = send_channel_test_message("carrier-pigeon", cfg)
    assert ok is False


def test_test_message_webhook_failure_reports_http_status_never_reason():
    import urllib.error

    sentinel = "SENTINEL_SECRET_DO_NOT_LEAK_hunter2"
    cfg = Config(alerts={"webhook": {"url": "https://example.com/hook", "enabled": True}})
    exc = urllib.error.HTTPError(url=cfg.alerts.webhook.url, code=502, msg=sentinel, hdrs=None, fp=None)
    with patch("lanfence.channels.urllib.request.urlopen", side_effect=exc):
        ok, message = send_channel_test_message("webhook", cfg)
    assert ok is False
    assert "502" in message
    assert sentinel not in message


def test_test_message_email_failure_reports_smtp_code_never_server_text(caplog):
    import logging
    import smtplib

    sentinel = "SENTINEL_SECRET_DO_NOT_LEAK_hunter2"
    cfg = Config(alerts={"email": {
        "from_addr": "lanfence@example.com", "to_addrs": ["ops@example.com"], "enabled": True,
    }})
    exc = smtplib.SMTPResponseException(535, f"{sentinel} auth failed".encode())
    with caplog.at_level(logging.ERROR):
        with patch("lanfence.channels.smtplib.SMTP", side_effect=exc):
            ok, message = send_channel_test_message("email", cfg)
    assert ok is False
    assert "535" in message
    assert sentinel not in message
    assert sentinel not in caplog.text


def test_test_message_twilio_failure_logs_never_contain_recipient_number(caplog):
    import logging
    import urllib.error

    sentinel = "SENTINEL_SECRET_DO_NOT_LEAK_hunter2"
    secret_number = "+15559998888"
    cfg = Config(alerts={"twilio": {
        "account_sid": "AC1", "auth_token": "tok", "from_number": "+15551234567",
        "to_numbers": [secret_number], "enabled": True,
    }})
    exc = urllib.error.HTTPError(url="https://api.twilio.com/x", code=400, msg=sentinel, hdrs=None, fp=None)
    with caplog.at_level(logging.ERROR):
        with patch("lanfence.channels.urllib.request.urlopen", side_effect=exc):
            ok, message = send_channel_test_message("twilio", cfg)
    assert ok is False
    assert secret_number not in caplog.text
    assert sentinel not in caplog.text
    assert secret_number not in message
    assert sentinel not in message
