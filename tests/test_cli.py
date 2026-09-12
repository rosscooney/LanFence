from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

from lanfence.cli import app
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.models import Finding

runner = CliRunner()


def _now():
    return datetime.now(timezone.utc)


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "db_path": str(tmp_path / "lanfence.db"),
                "allowlist_file": str(tmp_path / "allowlist.yaml"),
            }
        ),
        encoding="utf-8",
    )
    return path


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "lanfence" in result.stdout


def test_allow_list_empty(config_path: Path):
    result = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "empty" in result.stdout


def test_allow_add_then_list(config_path: Path):
    add = runner.invoke(app, ["allow", "aa:bb:cc:dd:ee:ff", "--name", "Router", "--config", str(config_path)])
    assert add.exit_code == 0, add.stdout
    assert "added" in add.stdout

    listed = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "Router" in listed.stdout
    assert "aa:bb:cc:dd:ee:ff" in listed.stdout


def test_allow_remove_unknown_mac_fails(config_path: Path):
    result = runner.invoke(app, ["allow", "--remove", "11:22:33:44:55:66", "--config", str(config_path)])
    assert result.exit_code == 2


def test_allow_remove_existing(config_path: Path):
    runner.invoke(app, ["allow", "aa:bb:cc:dd:ee:ff", "--name", "Router", "--config", str(config_path)])
    result = runner.invoke(app, ["allow", "--remove", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "removed" in result.stdout


def test_reset_noninteractive_without_yes_fails_helpfully(config_path: Path):
    _seed_devices(config_path)
    # No mock of _stdin_is_interactive - CliRunner's stdin is never a tty,
    # matching real noninteractive use (cron/systemd) - must fail helpfully,
    # not hang waiting for confirmation that will never come.
    result = runner.invoke(app, ["reset", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "--yes" in result.output
    by_mac = _devices_json(config_path)
    assert by_mac  # nothing was deleted


def test_reset_yes_flag_clears_devices_and_allowlist(config_path: Path):
    _seed_devices(config_path)  # includes an allowlisted device
    result = runner.invoke(app, ["reset", "--yes", "--config", str(config_path)])
    assert result.exit_code == 0

    assert _devices_json(config_path) == {}
    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "allowlist is empty" in listing.output.lower()


def test_reset_keep_allowlist_flag_leaves_trust_decisions_intact(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(app, ["reset", "--yes", "--keep-allowlist", "--config", str(config_path)])
    assert result.exit_code == 0

    assert _devices_json(config_path) == {}
    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "allowlist is empty" not in listing.output.lower()


def test_reset_interactive_confirm_yes(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(app, ["reset", "--config", str(config_path)], input="y\n")
    assert result.exit_code == 0
    assert _devices_json(config_path) == {}


def test_reset_interactive_confirm_no_aborts_without_changes(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(app, ["reset", "--config", str(config_path)], input="n\n")
    assert result.exit_code == 0
    assert "aborted" in result.output.lower()
    by_mac = _devices_json(config_path)
    assert by_mac  # nothing was deleted
    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "allowlist is empty" not in listing.output.lower()


def test_check_runs_without_crashing(config_path: Path):
    result = runner.invoke(app, ["check", "--config", str(config_path)])
    assert result.exit_code in (0, 1)
    assert "Host" in result.stdout


def test_check_creates_missing_allowlist_file(tmp_path: Path, config_path: Path):
    allowlist_file = tmp_path / "allowlist.yaml"
    assert not allowlist_file.exists()

    result = runner.invoke(app, ["check", "--config", str(config_path)])
    assert "(created)" in result.output
    assert allowlist_file.is_file()
    assert "allow: []" in allowlist_file.read_text()


def test_check_reports_existing_allowlist_file_unchanged(tmp_path: Path, config_path: Path):
    allowlist_file = tmp_path / "allowlist.yaml"
    allowlist_file.write_text("allow:\n  - mac: aa:bb:cc:dd:ee:ff\n    name: Router\n", encoding="utf-8")

    result = runner.invoke(app, ["check", "--config", str(config_path)])
    assert "(exists)" in result.output
    assert "Router" in allowlist_file.read_text()


def test_report_empty_db_json(config_path: Path):
    result = runner.invoke(app, ["report", "--since", "24h", "--format", "json", "--config", str(config_path)])
    assert result.exit_code == 0
    assert '"events": []' in result.stdout
    assert '"findings": []' in result.stdout


def test_report_bad_since_value(config_path: Path):
    result = runner.invoke(app, ["report", "--since", "nonsense", "--config", str(config_path)])
    assert result.exit_code == 2


# --- digest ------------------------------------------------------------


def test_digest_empty_database_preview(config_path: Path):
    result = runner.invoke(app, ["digest", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "LAN Fence digest" in result.output


def test_digest_json_output_has_schema_version_and_window(config_path: Path):
    import json

    result = runner.invoke(app, ["digest", "--format", "json", "--config", str(config_path)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schema_version"] == 1
    assert "window_start" in payload and "window_end" in payload and "generated_at" in payload


def test_digest_bad_since_value(config_path: Path):
    result = runner.invoke(app, ["digest", "--since", "nonsense", "--config", str(config_path)])
    assert result.exit_code == 2


def test_digest_rejects_invalid_format(config_path: Path):
    result = runner.invoke(app, ["digest", "--format", "xml", "--config", str(config_path)])
    assert result.exit_code == 2


def test_digest_preview_never_calls_a_transport(config_path: Path):
    """Default (no --send) must never touch the network - not even to
    validate destinations."""

    with patch("lanfence.digest.urllib.request.urlopen") as mock_open, \
         patch("lanfence.digest.smtplib.SMTP") as mock_smtp:
        result = runner.invoke(app, ["digest", "--config", str(config_path)])
    assert result.exit_code == 0
    mock_open.assert_not_called()
    mock_smtp.assert_not_called()


def test_digest_send_without_any_channel_configured_fails_helpfully(config_path: Path):
    result = runner.invoke(app, ["digest", "--send", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "channel" in result.output.lower()


def test_digest_send_rejects_unknown_channel(config_path: Path):
    result = runner.invoke(app, ["digest", "--send", "--channel", "carrier-pigeon", "--config", str(config_path)])
    assert result.exit_code == 2


def test_digest_send_rejects_sms_and_syslog_explicitly(config_path: Path):
    for bad in ("sms", "syslog"):
        result = runner.invoke(app, ["digest", "--send", "--channel", bad, "--config", str(config_path)])
        assert result.exit_code == 2
        assert "not supported" in result.output.lower() or "sms" in result.output.lower() or "syslog" in result.output.lower()


def test_digest_send_rejects_channel_not_enabled_in_config(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "alerts": {"webhook": {"enabled": False, "url": "https://example.com/hook"}},
            "digest": {"channels": ["webhook"]},
        }),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["digest", "--send", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "not enabled" in result.output.lower()


def test_digest_send_empty_digest_suppressed_by_default(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "alerts": {"webhook": {"enabled": True, "url": "https://example.com/hook"}},
            "digest": {"channels": ["webhook"]},
        }),
        encoding="utf-8",
    )
    with patch("lanfence.digest.urllib.request.urlopen") as mock_open:
        result = runner.invoke(app, ["digest", "--send", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "not sending" in result.output.lower()
    mock_open.assert_not_called()


def test_digest_send_empty_flag_overrides_suppression(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "alerts": {"webhook": {"enabled": True, "url": "https://example.com/hook"}},
            "digest": {"channels": ["webhook"]},
        }),
        encoding="utf-8",
    )

    class _FakeResp:
        def read(self):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("lanfence.digest.urllib.request.urlopen", return_value=_FakeResp()) as mock_open:
        result = runner.invoke(app, ["digest", "--send", "--send-empty", "--config", str(config_path)])
    assert result.exit_code == 0
    mock_open.assert_called_once()


def test_digest_send_success_reports_per_channel_and_exits_zero(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "alerts": {"webhook": {"enabled": True, "url": "https://example.com/hook"}},
            "digest": {"channels": ["webhook"]},
        }),
        encoding="utf-8",
    )
    store = DeviceStore(str(tmp_path / "lanfence.db"))
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now())
    store.close()

    class _FakeResp:
        def read(self):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("lanfence.digest.urllib.request.urlopen", return_value=_FakeResp()) as mock_open:
        result = runner.invoke(app, ["digest", "--send", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "webhook: sent" in result.output.lower()
    mock_open.assert_called_once()


def test_digest_send_failure_exits_nonzero(tmp_path: Path):
    import urllib.error

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "alerts": {"webhook": {"enabled": True, "url": "https://example.com/hook"}},
            "digest": {"channels": ["webhook"]},
        }),
        encoding="utf-8",
    )
    store = DeviceStore(str(tmp_path / "lanfence.db"))
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now())
    store.close()

    with patch("lanfence.digest.urllib.request.urlopen", side_effect=urllib.error.URLError("boom")):
        result = runner.invoke(app, ["digest", "--send", "--config", str(config_path)])
    assert result.exit_code == 1
    assert "failed" in result.output.lower()


def test_digest_channel_flag_limits_to_subset_of_configured_channels(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "alerts": {
                "webhook": {"enabled": True, "url": "https://example.com/hook"},
                "slack": {"enabled": True, "webhook_url": "https://hooks.slack.example/x"},
            },
            "digest": {"channels": ["webhook", "slack"]},
        }),
        encoding="utf-8",
    )
    store = DeviceStore(str(tmp_path / "lanfence.db"))
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now())
    store.close()

    class _FakeResp:
        def read(self):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("lanfence.digest.urllib.request.urlopen", return_value=_FakeResp()) as mock_open:
        result = runner.invoke(
            app, ["digest", "--send", "--channel", "slack", "--config", str(config_path)]
        )
    assert result.exit_code == 0
    assert "slack: sent" in result.output.lower()
    assert "webhook" not in result.output.lower()
    mock_open.assert_called_once()


def test_digest_does_not_change_alert_cooldown_state(tmp_path: Path):
    """Digest delivery must stay independent of the immediate-alert
    pipeline's per-MAC cooldown bookkeeping."""

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "alerts": {"webhook": {"enabled": True, "url": "https://example.com/hook"}},
            "digest": {"channels": ["webhook"]},
        }),
        encoding="utf-8",
    )
    db_path = str(tmp_path / "lanfence.db")
    store = DeviceStore(db_path)
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now())
    store.close()

    class _FakeResp:
        def read(self):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("lanfence.digest.urllib.request.urlopen", return_value=_FakeResp()):
        runner.invoke(app, ["digest", "--send", "--config", str(config_path)])

    store = DeviceStore(db_path)
    still_due = store.due_for_alert("aa:bb:cc:dd:ee:ff", "medium", now=_now(), cooldown_seconds=900)
    store.close()
    assert still_due is True  # digest sending never touched alert_log for this mac


def test_scan_without_permission_reports_error_gracefully(config_path: Path):
    # No root/CAP_NET_RAW in the test environment - scan should degrade to an
    # error message and a clean (empty) result rather than crashing.
    result = runner.invoke(app, ["scan", "--subnet", "192.0.2.0/29", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "No devices responded" in result.stdout or "devices" in result.stdout.lower()


def test_check_reports_ipv6_line(config_path: Path):
    result = runner.invoke(app, ["check", "--config", str(config_path)])
    assert "ipv6:" in result.output


def test_run_is_an_alias_for_scan(config_path: Path):
    with patch("lanfence.cli.run_active_sweep") as sweep_mock:
        sweep_mock.return_value.findings = []
        sweep_mock.return_value.errors = []
        sweep_mock.return_value.to_json.return_value = "{}"
        result = runner.invoke(app, ["run", "--config", str(config_path)])
    assert result.exit_code == 0
    sweep_mock.assert_called_once()


def test_scan_trusts_its_own_mac(config_path: Path, monkeypatch):
    """LAN Fence's own MAC - inevitably visible to its own active sweep or a
    concurrent passive capture - must never be treated as an unknown device."""

    from lanfence import scanner as scanner_module

    self_mac = "aa:bb:cc:dd:ee:ff"
    sighting = scanner_module.ArpSighting(mac=self_mac, ip="10.0.0.9", seen_at=_now())

    monkeypatch.setattr("lanfence.cli.scanner.local_mac", lambda iface=None: self_mac)
    monkeypatch.setattr("lanfence.cli.scanner.active_scan", lambda *, subnet, interface=None, timeout=3.0: [sighting])
    monkeypatch.setattr("lanfence.cli.scanner.local_subnet", lambda iface=None: "10.0.0.0/24")
    monkeypatch.setattr("lanfence.cli.scanner.default_interface", lambda: "eth0")

    result = runner.invoke(app, ["scan", "--no-ipv6", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Unknown device" not in result.output

    by_mac = _devices_json(config_path)
    assert by_mac[self_mac]["allowlisted"] is True


def test_scan_no_ipv6_flag_disables_ipv6_scanning(config_path: Path):
    with patch("lanfence.cli.run_active_sweep") as sweep_mock:
        sweep_mock.return_value.findings = []
        sweep_mock.return_value.errors = []
        sweep_mock.return_value.to_json.return_value = "{}"
        runner.invoke(app, ["scan", "--no-ipv6", "--config", str(config_path)])
    passed_cfg = sweep_mock.call_args.args[0]
    assert passed_cfg.scan.ipv6 is False


def test_monitor_no_ipv6_flag_is_reflected_in_banner(config_path: Path, monkeypatch):
    # monitor() loops forever; stop it after the startup banner is printed by
    # making the first thing it does (the scan-interval sleep loop) raise.
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--no-ipv6", "--no-passive", "--config", str(config_path)])
    assert "ipv6: False" in result.output


def test_monitor_no_dhcp_flag_is_reflected_in_banner(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--no-dhcp", "--no-passive", "--config", str(config_path)])
    assert "dhcp: False" in result.output


def test_monitor_dhcp_disabled_when_passive_disabled_even_if_dhcp_flag_true(config_path: Path, monkeypatch):
    # dhcp_active in the banner is passive AND dhcp_snooping - --no-passive
    # alone should already show dhcp: False, since DHCP snooping needs the
    # capture running at all.
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--dhcp", "--no-passive", "--config", str(config_path)])
    assert "dhcp: False" in result.output


def test_monitor_dhcp_server_detection_banner_off_by_default(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--no-passive", "--config", str(config_path)])
    assert "dhcp-server-detection: False" in result.output


def test_monitor_dhcp_server_detection_warns_when_enabled_but_passive_off(tmp_path: Path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "scan": {"passive": False},
            "dhcp_servers": {"enabled": True},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--config", str(config_path)])
    assert "dhcp-server-detection: False" in result.output
    assert "passive DHCP capture is off" in result.output


def test_monitor_dhcp_server_detection_warns_when_no_approvals(tmp_path: Path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "dhcp_servers": {"enabled": True, "approved": []},
        }),
        encoding="utf-8",
    )
    from lanfence import scanner as scanner_module

    def fake_passive_sniff(**kwargs):
        raise scanner_module.ScannerUnavailable("n/a")

    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    monkeypatch.setattr("lanfence.cli.scanner.passive_sniff", fake_passive_sniff)
    result = runner.invoke(app, ["monitor", "--config", str(config_path)])
    assert "every DHCP server observed will be treated as unexpected" in result.output


# --- dhcp-servers --------------------------------------------------------


def test_dhcp_servers_empty_inventory(config_path: Path):
    result = runner.invoke(app, ["dhcp-servers", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "No DHCP server replies observed" in result.output


def _seed_dhcp_server(config_path: Path, *, interface="eth0", server_id="192.168.1.66") -> None:
    from lanfence.dhcp_server import process_dhcp_server_sighting
    from lanfence.scanner import DhcpServerSighting

    cfg_dict = yaml.safe_load(config_path.read_text())
    cfg = Config.load(config_path)
    store = DeviceStore(cfg_dict["db_path"])
    process_dhcp_server_sighting(
        DhcpServerSighting(
            interface=interface, server_id=server_id, message_type="offer", observed_at=_now(),
            source_ip=server_id, source_mac="bb:bb:bb:bb:bb:bb",
        ),
        store, cfg,
    )
    store.close()


def test_dhcp_servers_lists_observed_server(config_path: Path):
    _seed_dhcp_server(config_path)
    result = runner.invoke(app, ["dhcp-servers", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "192.168.1.66" in result.output
    assert "NOT approved" in result.output


def test_dhcp_servers_json_output_has_no_mac_field_but_has_server_id(config_path: Path):
    import json

    _seed_dhcp_server(config_path)
    result = runner.invoke(app, ["dhcp-servers", "--format", "json", "--config", str(config_path)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["server_id"] == "192.168.1.66"
    assert payload[0]["approved"] is False


def test_dhcp_servers_shows_approved_status_and_name(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "dhcp_servers": {
                "enabled": True,
                "approved": [{"interface": "eth0", "server_ip": "192.168.1.1", "name": "Main Router"}],
            },
        }),
        encoding="utf-8",
    )
    _seed_dhcp_server(config_path, server_id="192.168.1.1")
    result = runner.invoke(app, ["dhcp-servers", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Main Router" in result.output
    assert "NOT approved" not in result.output


def test_dhcp_servers_rejects_invalid_format(config_path: Path):
    result = runner.invoke(app, ["dhcp-servers", "--format", "xml", "--config", str(config_path)])
    assert result.exit_code == 2


def test_dhcp_servers_is_read_only_never_scans(config_path: Path):
    with patch("lanfence.cli.scanner.active_scan") as mock_scan, \
         patch("lanfence.cli.scanner.passive_sniff") as mock_sniff:
        result = runner.invoke(app, ["dhcp-servers", "--config", str(config_path)])
    assert result.exit_code == 0
    mock_scan.assert_not_called()
    mock_sniff.assert_not_called()


class _FakeUrlopenResponse:
    def read(self):
        return b""

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def test_scan_alert_rate_limits_repeat_dispatch_for_same_device(tmp_path: Path):
    """Integration test: `scan --alert` run twice in a row against the same
    database only dispatches to the configured webhook once for a device
    whose finding didn't escalate, thanks to the alerts.rate_limit_seconds
    cooldown (default 900s - well within two back-to-back test runs)."""

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "alerts": {"webhook": {"enabled": True, "url": "https://example.com/hook"}},
        }),
        encoding="utf-8",
    )

    finding = Finding(mac="aa:bb:cc:dd:ee:ff", title="Unknown device connected", severity="high")
    fake_result = type("R", (), {
        "findings": [finding],
        "errors": [],
        "to_json": lambda self: "{}",
    })()

    with patch("lanfence.cli.run_active_sweep", return_value=fake_result), \
         patch("lanfence.alerts.urllib.request.urlopen", return_value=_FakeUrlopenResponse()) as urlopen_mock:
        runner.invoke(app, ["scan", "--alert", "--config", str(config_path)])
        runner.invoke(app, ["scan", "--alert", "--config", str(config_path)])

    assert urlopen_mock.call_count == 1


def test_config_not_found(tmp_path: Path):
    result = runner.invoke(app, ["allow", "--list", "--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code == 2


# --- devices ---------------------------------------------------------------


def _seed_devices(config_path: Path) -> None:
    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    now = _now()
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname="phone.local", vendor="Apple, Inc.", seen_at=now)
    store.observe(mac="11:22:33:44:55:66", ip="10.0.0.6", hostname=None, vendor="Espressif Inc.", seen_at=now)
    store.observe(mac="77:88:99:aa:bb:cc", ip="10.0.0.7", hostname="nas.local", vendor=None, seen_at=now)
    store.mark_offline({"aa:bb:cc:dd:ee:ff", "77:88:99:aa:bb:cc"}, as_of=now)  # offlines 11:22:33
    store.set_investigating("77:88:99:aa:bb:cc", notes="check", updated_at=now)
    store.close()

    from lanfence.allowlist import Allowlist

    al = Allowlist.load(cfg_dict["allowlist_file"])
    al.path = Path(cfg_dict["allowlist_file"])
    al.add("aa:bb:cc:dd:ee:ff", "My Phone")
    al.save()


def test_devices_empty_database(config_path: Path):
    result = runner.invoke(app, ["devices", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "database yet" in result.output.lower()


def _devices_json(config_path: Path, *extra_args: str) -> dict:
    import json

    result = runner.invoke(app, ["devices", "--format", "json", *extra_args, "--config", str(config_path)])
    assert result.exit_code == 0, result.output
    return {d["mac"]: d for d in json.loads(result.output)}


def test_devices_lists_all_by_default(config_path: Path):
    _seed_devices(config_path)
    by_mac = _devices_json(config_path)
    assert set(by_mac) == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "77:88:99:aa:bb:cc"}

    # the table format renders without crashing and reports the right count
    result = runner.invoke(app, ["devices", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Devices (3)" in result.output


def test_devices_status_filter(config_path: Path):
    _seed_devices(config_path)
    by_mac = _devices_json(config_path, "--status", "offline")
    assert set(by_mac) == {"11:22:33:44:55:66"}


def test_devices_untrusted_filter(config_path: Path):
    _seed_devices(config_path)
    by_mac = _devices_json(config_path, "--untrusted")
    assert set(by_mac) == {"11:22:33:44:55:66", "77:88:99:aa:bb:cc"}


def test_devices_review_needed_filter_excludes_trusted_and_investigating(config_path: Path):
    _seed_devices(config_path)
    by_mac = _devices_json(config_path, "--review-needed")
    assert set(by_mac) == {"11:22:33:44:55:66"}


def test_devices_combined_filters_are_predictable_and(config_path: Path):
    _seed_devices(config_path)
    # untrusted AND offline -> only 11:22:33 (77:88:99 is untrusted but online)
    by_mac = _devices_json(config_path, "--untrusted", "--status", "offline")
    assert set(by_mac) == {"11:22:33:44:55:66"}


def test_devices_presence_filter(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(app, ["device", "11:22:33:44:55:66", "--presence", "intermittent", "--config", str(config_path)])
    runner.invoke(app, ["device", "77:88:99:aa:bb:cc", "--presence", "always-on", "--config", str(config_path)])

    assert set(_devices_json(config_path, "--presence", "intermittent")) == {"11:22:33:44:55:66"}
    assert set(_devices_json(config_path, "--presence", "always-on")) == {"77:88:99:aa:bb:cc"}
    assert set(_devices_json(config_path, "--presence", "unspecified")) == {"aa:bb:cc:dd:ee:ff"}


def test_devices_rejects_invalid_presence(config_path: Path):
    result = runner.invoke(app, ["devices", "--presence", "sometimes", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "presence" in result.output.lower()


def test_devices_json_output(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(app, ["devices", "--format", "json", "--config", str(config_path)])
    assert result.exit_code == 0
    import json

    payload = json.loads(result.output)
    assert len(payload) == 3
    by_mac = {d["mac"]: d for d in payload}
    assert by_mac["aa:bb:cc:dd:ee:ff"]["allowlisted"] is True
    assert by_mac["77:88:99:aa:bb:cc"]["review_state"] == "investigating"


def test_devices_rejects_invalid_status(config_path: Path):
    result = runner.invoke(app, ["devices", "--status", "sideways", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "status" in result.output.lower()


def test_devices_rejects_invalid_format(config_path: Path):
    result = runner.invoke(app, ["devices", "--format", "xml", "--config", str(config_path)])
    assert result.exit_code == 2


# --- device <mac> ------------------------------------------------------


def test_device_shows_current_details_and_timeline(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Current details" in result.output
    assert "Lifecycle timeline" in result.output
    assert "phone.local" in result.output
    assert "trusted" in result.output.lower()


def test_device_since_filters_timeline(config_path: Path):
    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    old = _now() - timedelta(days=10)
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=old)
    store.mark_offline(set(), as_of=old + timedelta(minutes=1))
    store.observe(
        mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None,
        seen_at=_now(),
    )
    store.close()

    result_all = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--since", "365d", "--config", str(config_path)]
    )
    assert "3 event(s)" in result_all.output  # new_device, disconnected, reappeared

    result_recent = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--since", "1h", "--config", str(config_path)]
    )
    assert "1 event(s)" in result_recent.output  # only the recent reappeared


def test_device_json_output(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--format", "json", "--config", str(config_path)])
    assert result.exit_code == 0
    import json

    payload = json.loads(result.output)
    assert payload["device"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert "timeline" in payload
    assert "since" in payload
    assert "addresses" in payload
    assert "names" in payload
    assert payload["addresses"][0]["ip"] == "10.0.0.5"
    assert payload["addresses"][0]["source"] == "arp"


def test_device_invalid_mac(config_path: Path):
    result = runner.invoke(app, ["device", "not-a-mac", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "not a valid mac" in result.output.lower()


# --- device <mac> --presence -------------------------------------------


def test_device_shows_presence_unspecified_by_default(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert "Presence: unspecified" in result.output


def test_device_set_presence_intermittent(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--presence", "intermittent", "--config", str(config_path)]
    )
    assert result.exit_code == 0
    assert "intermittent" in result.output.lower()

    show = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert "Presence: intermittent" in show.output


def test_device_set_always_on_with_offline_after(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--presence", "always-on", "--offline-after", "10m",
              "--config", str(config_path)],
    )
    assert result.exit_code == 0

    show = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert "Presence: always-on" in show.output
    assert "600s" in show.output


def test_device_read_only_when_no_mutation_options_given(config_path: Path):
    """Preserve existing read-only behavior: no presence flags means show,
    same as before this feature existed."""

    _seed_devices(config_path)
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Current details" in result.output


def test_device_offline_after_rejected_when_not_always_on(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--offline-after", "10m", "--config", str(config_path)]
    )
    assert result.exit_code == 2
    assert "always-on" in result.output.lower()


def test_device_offline_after_rejected_when_presence_given_as_something_else(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--presence", "intermittent", "--offline-after", "10m",
              "--config", str(config_path)],
    )
    assert result.exit_code == 2
    assert "always-on" in result.output.lower()


def test_device_offline_after_and_clear_offline_after_are_contradictory(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--offline-after", "10m", "--clear-offline-after",
              "--config", str(config_path)],
    )
    assert result.exit_code == 2
    assert "contradictory" in result.output.lower()


def test_device_clear_offline_after_restores_global_default(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--presence", "always-on", "--offline-after", "10m",
              "--config", str(config_path)],
    )
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--clear-offline-after", "--config", str(config_path)]
    )
    assert result.exit_code == 0

    show = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert "180s" in show.output  # the default scan.offline_grace_seconds


def test_device_switching_away_from_always_on_clears_override(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--presence", "always-on", "--offline-after", "10m",
              "--config", str(config_path)],
    )
    runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--presence", "intermittent", "--config", str(config_path)])

    by_mac = _devices_json(config_path)
    assert by_mac["aa:bb:cc:dd:ee:ff"]["offline_after_seconds"] is None


def test_device_rejects_invalid_presence_value(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--presence", "sometimes", "--config", str(config_path)]
    )
    assert result.exit_code == 2


def test_device_presence_unknown_mac_fails(config_path: Path):
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--presence", "intermittent", "--config", str(config_path)]
    )
    assert result.exit_code == 2
    assert "no device" in result.output.lower()


def test_device_presence_json_output_is_additive(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--presence", "always-on", "--offline-after", "5m",
              "--config", str(config_path)],
    )
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--format", "json", "--config", str(config_path)])
    import json

    payload = json.loads(result.output)
    assert payload["device"]["presence_policy"] == "always-on"
    assert payload["device"]["offline_after_seconds"] == 300.0


def test_device_unknown_mac(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(app, ["device", "00:00:00:00:00:99", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "no device" in result.output.lower()


def test_device_normalizes_mac_case_and_separators(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(app, ["device", "AA-BB-CC-DD-EE-FF", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "aa:bb:cc:dd:ee:ff" in result.output


# --- review: noninteractive -------------------------------------------------


def test_review_trust_adds_to_allowlist_and_clears_review_flag(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["review", "11:22:33:44:55:66", "--trust", "--name", "Kitchen speaker",
              "--notes", "smart plug", "--config", str(config_path)],
    )
    assert result.exit_code == 0
    assert "trusted" in result.output.lower()

    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "Kitchen speaker" in listing.output

    devices_result = runner.invoke(app, ["devices", "--format", "json", "--config", str(config_path)])
    import json

    payload = {d["mac"]: d for d in json.loads(devices_result.output)}
    assert payload["11:22:33:44:55:66"]["allowlisted"] is True


def test_review_trust_defaults_name_to_mac(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(app, ["review", "11:22:33:44:55:66", "--trust", "--config", str(config_path)])
    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "11:22:33:44:55:66" in listing.output


def test_review_snooze_sets_snoozed_state(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["review", "11:22:33:44:55:66", "--snooze", "24h", "--config", str(config_path)]
    )
    assert result.exit_code == 0
    assert "snoozed" in result.output.lower()

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    review = store.get_review("11:22:33:44:55:66")
    store.close()
    assert review.state == "snoozed"
    assert review.snoozed_until > _now()


def test_review_investigate_sets_flag_without_trusting_or_snoozing(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["review", "11:22:33:44:55:66", "--investigate", "--notes", "weird device",
              "--config", str(config_path)],
    )
    assert result.exit_code == 0

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    review = store.get_review("11:22:33:44:55:66")
    store.close()
    assert review.state == "investigating"
    assert review.notes == "weird device"

    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "11:22:33:44:55:66" not in listing.output  # not trusted


def test_review_clear_removes_flags_but_not_allowlist(config_path: Path):
    _seed_devices(config_path)
    # 77:88:99 was set to investigating by _seed_devices
    result = runner.invoke(
        app, ["review", "77:88:99:aa:bb:cc", "--clear", "--config", str(config_path)]
    )
    assert result.exit_code == 0

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    review = store.get_review("77:88:99:aa:bb:cc")
    store.close()
    assert review.state == "pending"

    # aa:bb:cc:dd:ee:ff is trusted by _seed_devices; clearing its review
    # state (a no-op here, it has none) must not touch the allowlist either.
    runner.invoke(app, ["review", "aa:bb:cc:dd:ee:ff", "--clear", "--config", str(config_path)])
    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "My Phone" in listing.output


def test_review_rejects_no_action_given(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(app, ["review", "11:22:33:44:55:66", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "exactly one" in result.output.lower()


def test_review_rejects_conflicting_actions(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["review", "11:22:33:44:55:66", "--trust", "--investigate", "--config", str(config_path)]
    )
    assert result.exit_code == 2
    assert "exactly one" in result.output.lower()


def test_review_rejects_name_without_trust(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["review", "11:22:33:44:55:66", "--investigate", "--name", "x", "--config", str(config_path)]
    )
    assert result.exit_code == 2
    assert "--name" in result.output


def test_review_rejects_notes_without_trust_or_investigate(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["review", "11:22:33:44:55:66", "--snooze", "24h", "--notes", "x", "--config", str(config_path)]
    )
    assert result.exit_code == 2
    assert "--notes" in result.output


def test_review_rejects_action_flags_without_mac(config_path: Path):
    result = runner.invoke(app, ["review", "--trust", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "require a mac" in result.output.lower()


def test_review_rejects_invalid_mac_noninteractive(config_path: Path):
    result = runner.invoke(app, ["review", "not-a-mac", "--trust", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "not a valid mac" in result.output.lower()


def test_review_rejects_invalid_snooze_duration(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["review", "11:22:33:44:55:66", "--snooze", "sideways", "--config", str(config_path)]
    )
    assert result.exit_code == 2


# --- review: interactive ----------------------------------------------------


def test_review_interactive_requires_a_terminal(config_path: Path):
    _seed_devices(config_path)
    # No mock of _stdin_is_interactive - CliRunner's stdin is never a tty,
    # matching real noninteractive use (cron/systemd) - must fail helpfully,
    # not hang waiting for input that will never come.
    result = runner.invoke(app, ["review", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "interactive terminal" in result.output.lower()


def test_review_interactive_nothing_to_review(config_path: Path):
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(app, ["review", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "nothing needs review" in result.output.lower()


def test_review_interactive_trust_flow(config_path: Path):
    _seed_devices(config_path)  # 11:22:33 needs review; aa:bb:cc trusted; 77:88:99 investigating
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="t\nLiving Room ESP\nsome notes\n",
        )
    assert result.exit_code == 0
    assert "trusted: living room esp" in result.output.lower()

    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "Living Room ESP" in listing.output


def test_review_interactive_trust_then_presence_intermittent(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="t\nLiving Room ESP\nsome notes\ni\n",
        )
    assert result.exit_code == 0
    assert "presence: intermittent" in result.output.lower()

    by_mac = _devices_json(config_path)
    assert by_mac["11:22:33:44:55:66"]["presence_policy"] == "intermittent"


def test_review_interactive_trust_then_presence_always_on(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="t\nNAS\n\na\n",
        )
    assert result.exit_code == 0
    assert "presence: always-on" in result.output.lower()


def test_review_interactive_trust_then_presence_prompt_aborted_preserves_trust(config_path: Path):
    """Exiting the presence sub-prompt (EOF here, standing in for Ctrl+D/C)
    must not undo the trust decision made moments before."""

    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="t\nLiving Room ESP\nsome notes\n",  # no answer for the presence prompt
        )
    assert result.exit_code == 0
    assert "presence unchanged" in result.output.lower()

    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "Living Room ESP" in listing.output  # trust was preserved

    by_mac = _devices_json(config_path)
    assert by_mac["11:22:33:44:55:66"]["presence_policy"] == "unspecified"  # left at the default


def test_review_interactive_snooze_flow(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="s\n2h\n",
        )
    assert result.exit_code == 0
    assert "snoozed until" in result.output.lower()

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    review = store.get_review("11:22:33:44:55:66")
    store.close()
    assert review.state == "snoozed"


def test_review_interactive_investigate_flow(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="i\nlooks odd\n",
        )
    assert result.exit_code == 0
    assert "flagged for investigation" in result.output.lower()

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    review = store.get_review("11:22:33:44:55:66")
    store.close()
    assert review.state == "investigating"
    assert review.notes == "looks odd"


def test_review_interactive_skip_makes_no_changes(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(app, ["review", "--config", str(config_path)], input="k\n")
    assert result.exit_code == 0

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    review = store.get_review("11:22:33:44:55:66")
    store.close()
    assert review.state == "pending"


def test_review_interactive_quit_preserves_earlier_decisions(config_path: Path):
    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    now = _now()
    store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=now)
    store.observe(mac="11:22:33:44:55:66", ip="10.0.0.6", hostname=None, vendor=None, seen_at=now)
    store.close()

    # queue order is by MAC ascending: 11:22:... comes before aa:bb:...
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="i\nfirst device flagged\nq\n",
        )
    assert result.exit_code == 0
    assert "stopping review" in result.output.lower()

    store = DeviceStore(cfg_dict["db_path"])
    first_review = store.get_review("11:22:33:44:55:66")
    second_review = store.get_review("aa:bb:cc:dd:ee:ff")
    store.close()
    assert first_review.state == "investigating"  # decision before quit preserved
    assert second_review.state == "pending"  # never reached


# --- monitor picking up live trust changes ----------------------------------


def test_monitor_picks_up_trust_change_without_restart(tmp_path: Path, monkeypatch):
    from lanfence import scanner as scanner_module
    from lanfence.allowlist import Allowlist

    db_path = tmp_path / "lanfence.db"
    allowlist_path = tmp_path / "allowlist.yaml"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(db_path),
            "allowlist_file": str(allowlist_path),
            "scan": {
                "scan_interval_seconds": 0.001, "resolve_hostnames": False,
                # Compatibility settings: disconnect on the device's very
                # first missed sweep (sweep 2 below), rather than waiting out
                # the default grace period/miss threshold - this test is
                # about trust-reload timing, not the grace period itself.
                "offline_grace_seconds": 0, "offline_after_missed_scans": 1,
            },
        }),
        encoding="utf-8",
    )

    # First octet 0x00 has the locally-administered bit clear and matches no
    # vendor OUI, so this MAC triggers no fingerprint signature - keeping the
    # "not yet trusted" severity a plain "medium" (see build_findings), not
    # complicated by an unrelated info-severity signature match.
    sighting_mac = "00:11:22:33:44:55"

    # A routine "still online, nothing changed" sighting produces no finding
    # at all (see build_findings) - to observe the reloaded trust state
    # reflected in a *new* finding, the device must disconnect and reappear:
    # present on sweeps 1 and 3, absent (marked offline) on sweep 2.
    sweep = {"n": 0}

    def fake_active_scan(*, subnet, interface=None, timeout=3.0):
        sweep["n"] += 1
        if sweep["n"] == 2:
            return []
        return [scanner_module.ArpSighting(mac=sighting_mac, ip="10.0.0.5", seen_at=_now())]

    monkeypatch.setattr("lanfence.cli.scanner.active_scan", fake_active_scan)
    monkeypatch.setattr("lanfence.cli.scanner.local_subnet", lambda iface=None: "10.0.0.0/24")
    monkeypatch.setattr("lanfence.cli.scanner.default_interface", lambda: "eth0")

    findings_seen: list[list] = []

    def fake_emit_findings(findings, *, alert, cfg, store):
        findings_seen.append(list(findings))

    monkeypatch.setattr("lanfence.cli._emit_findings", fake_emit_findings)

    # The monitor loop only re-sweeps once `scan_interval_seconds` of
    # `time.monotonic()` has elapsed since the last sweep. With real
    # monotonic time and a mocked (non-blocking) sleep, consecutive loop
    # iterations can execute within the same sub-millisecond tick and
    # spuriously skip a sweep. Pin monotonic time to a controlled,
    # always-advancing counter so every iteration deterministically sweeps.
    clock = {"t": 0.0}

    def fake_monotonic():
        clock["t"] += 1.0
        return clock["t"]

    monkeypatch.setattr("lanfence.cli.time.monotonic", fake_monotonic)

    tick = {"n": 0}

    def fake_sleep(_seconds):
        tick["n"] += 1
        if tick["n"] == 1:
            # Simulate a concurrent `lanfence review --trust` (or `allow`)
            # happening while this monitor keeps running.
            al = Allowlist.load(allowlist_path)
            al.path = allowlist_path
            al.add(sighting_mac, "Trusted Mid-Run")
            al.save()
        if tick["n"] >= 3:
            raise KeyboardInterrupt

    monkeypatch.setattr("lanfence.cli.time.sleep", fake_sleep)

    result = runner.invoke(
        app, ["monitor", "--no-passive", "--no-ipv6", "--config", str(config_path)]
    )

    assert result.exit_code == 0
    assert len(findings_seen) == 3
    # Sweep 1 (new_device): not yet trusted.
    assert findings_seen[0][0].severity != "info"
    assert "unknown" in findings_seen[0][0].title.lower()
    # Sweep 2: the device dropped off (disconnected) - no finding either way.
    assert findings_seen[1] == []
    # Sweep 3 (reappeared): the allowlist reload picked up the trust change
    # made between sweeps 1 and 2, without restarting the monitor process.
    assert findings_seen[2][0].severity == "info"
    assert findings_seen[2][0].mac == sighting_mac


def test_monitor_queued_passive_sighting_prevents_false_disconnect_reappear(
    tmp_path: Path, monkeypatch
):
    """Regression test for the ordering fix: a passive sighting sitting in
    the queue at the moment an active sweep's absence check runs must be
    incorporated first - otherwise a device that never actually left would
    get a spurious disconnected event immediately followed by a reappeared
    one, in the same tick, once the queue is finally drained."""

    from lanfence import scanner as scanner_module

    db_path = tmp_path / "lanfence.db"
    allowlist_path = tmp_path / "allowlist.yaml"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(db_path),
            "allowlist_file": str(allowlist_path),
            "scan": {
                "scan_interval_seconds": 0.001, "resolve_hostnames": False,
                "interface": "eth0", "subnet": "10.0.0.0/24",
                "offline_grace_seconds": 180, "offline_after_missed_scans": 1,
            },
        }),
        encoding="utf-8",
    )

    sighting_mac = "00:11:22:33:44:55"

    # Seeded as already online but last positively seen an hour ago (well
    # past the 180s grace period) and with a clean miss count - if the
    # active sweep's absence check ran *before* the queued passive sighting
    # below were incorporated, this alone would be enough to disconnect it.
    old = _now() - timedelta(hours=1)
    with DeviceStore(db_path) as store:
        store.observe(
            mac=sighting_mac, ip="10.0.0.5", hostname=None, vendor=None, seen_at=old,
            interface="eth0", subnet="10.0.0.0/24",
        )

    class _SyncThread:
        """Runs the passive-sniff "thread" inline, synchronously, before the
        monitor loop starts - so the queued sighting below is deterministically
        present for the very first drain, with no real thread-scheduling race."""

        def __init__(self, target=None, **_kwargs):
            self._target = target

        def start(self) -> None:
            self._target()

    def fake_passive_sniff(*, on_sighting, interface=None, stop_event=None, dhcp=True, on_dhcp_server=None):
        on_sighting(scanner_module.ArpSighting(mac=sighting_mac, ip="10.0.0.5", seen_at=_now()))

    monkeypatch.setattr("lanfence.cli.threading.Thread", _SyncThread)
    monkeypatch.setattr("lanfence.cli.scanner.passive_sniff", fake_passive_sniff)
    monkeypatch.setattr(
        "lanfence.cli.scanner.active_scan",
        lambda *, subnet, interface=None, timeout=3.0: [],  # the active sweep itself misses it
    )
    monkeypatch.setattr("lanfence.cli.scanner.local_subnet", lambda iface=None: "10.0.0.0/24")
    monkeypatch.setattr("lanfence.cli.scanner.default_interface", lambda: "eth0")
    monkeypatch.setattr(
        "lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt)
    )

    result = runner.invoke(app, ["monitor", "--no-ipv6", "--config", str(config_path)])
    assert result.exit_code == 0

    with DeviceStore(db_path) as store:
        device = store.get_device(sighting_mac)
        events = store.events_for(sighting_mac)

    assert device.status == "online"
    # Only the original seeding event - no spurious disconnected/reappeared
    # pair generated within this tick.
    assert [e.event_type for e in events] == ["new_device"]
