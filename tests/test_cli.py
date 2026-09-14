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


# --- allow: interactive device-context confirmation -------------------------


def test_allow_interactive_shows_dossier_before_confirming_known_device(config_path: Path):
    _seed_devices(config_path)  # 11:22:33:44:55:66 is already observed, not yet trusted
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["allow", "11:22:33:44:55:66", "--config", str(config_path)], input="y\n",
        )
    assert result.exit_code == 0, result.output
    assert "Espressif Inc." in result.output  # dossier context shown before the prompt
    assert "Trust 11:22:33:44:55:66?" in result.output
    assert "added:" in result.output.lower()

    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "11:22:33:44:55:66" in listing.output


def test_allow_interactive_decline_makes_no_changes(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["allow", "11:22:33:44:55:66", "--config", str(config_path)], input="n\n",
        )
    assert result.exit_code == 0, result.output
    assert "cancelled" in result.output.lower()

    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "11:22:33:44:55:66" not in listing.output


def test_allow_interactive_unknown_device_skips_confirmation(config_path: Path):
    # A MAC never observed has no dossier to show - adding it directly (the
    # existing behavior) must still work unprompted even when interactive.
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["allow", "aa:11:22:33:44:55", "--name", "New Thing", "--config", str(config_path)],
        )
    assert result.exit_code == 0, result.output
    assert "added" in result.output.lower()


def test_allow_yes_flag_skips_confirmation_even_when_interactive(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["allow", "11:22:33:44:55:66", "--yes", "--config", str(config_path)],
        )
    assert result.exit_code == 0, result.output
    assert "Trust 11:22:33:44:55:66?" not in result.output
    assert "added" in result.output.lower()


def test_allow_noninteractive_never_prompts_for_known_device(config_path: Path):
    # CliRunner's stdin is never a tty - scripted/cron use must be completely
    # unaffected by the new confirmation, with no _stdin_is_interactive patch.
    _seed_devices(config_path)
    result = runner.invoke(app, ["allow", "11:22:33:44:55:66", "--config", str(config_path)])
    assert result.exit_code == 0, result.output
    assert "Trust 11:22:33:44:55:66?" not in result.output
    assert "added" in result.output.lower()


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


# --- scan: first-run triage summary -----------------------------------------


def _scan_with_sightings(config_path: Path, monkeypatch, sightings, *, extra_args=()):
    monkeypatch.setattr("lanfence.cli.scanner.active_scan", lambda *, subnet, interface=None, timeout=3.0: sightings)
    monkeypatch.setattr("lanfence.cli.scanner.local_subnet", lambda iface=None: "10.0.0.0/24")
    monkeypatch.setattr("lanfence.cli.scanner.default_interface", lambda: "eth0")
    monkeypatch.setattr("lanfence.cli.scanner.local_mac", lambda iface=None: None)
    return runner.invoke(app, ["scan", "--no-ipv6", *extra_args, "--config", str(config_path)])


def test_scan_table_output_shows_triage_summary(config_path: Path, monkeypatch):
    from lanfence import scanner as scanner_module

    sightings = [
        scanner_module.ArpSighting(mac="b8:e9:37:11:22:33", ip="10.0.0.10", seen_at=_now()),  # Sonos, straightforward
        scanner_module.ArpSighting(mac="00:11:22:33:44:55", ip="10.0.0.11", seen_at=_now()),  # unknown vendor
        scanner_module.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.12", seen_at=_now()),  # locally administered
        scanner_module.ArpSighting(mac="b8:27:eb:11:22:33", ip="10.0.0.13", seen_at=_now()),  # raspberry pi
    ]
    result = _scan_with_sightings(config_path, monkeypatch, sightings)
    assert result.exit_code == 0, result.output
    assert "LAN Fence has discovered 4 devices." in result.output
    assert "None have been reviewed yet." in result.output
    assert "Run `lanfence review` to work through them." in result.output


def test_scan_json_output_omits_triage_summary_and_stays_stable(config_path: Path, monkeypatch):
    import json

    from lanfence import scanner as scanner_module

    sightings = [scanner_module.ArpSighting(mac="b8:e9:37:11:22:33", ip="10.0.0.10", seen_at=_now())]
    result = _scan_with_sightings(config_path, monkeypatch, sightings, extra_args=["--format", "json"])
    assert result.exit_code == 0, result.output
    assert "LAN Fence has discovered" not in result.output

    lines = result.output.strip().splitlines()
    json_start = next(i for i, ln in enumerate(lines) if ln.strip().startswith("{"))
    data = json.loads("\n".join(lines[json_start:]))
    assert set(data.keys()) == {
        "started_at", "ended_at", "interface", "subnet", "mode", "devices", "events", "findings", "errors",
    }


def test_scan_triage_summary_reflects_already_trusted_devices(config_path: Path, monkeypatch):
    from lanfence import scanner as scanner_module

    sightings = [scanner_module.ArpSighting(mac="aa:11:22:33:44:55", ip="10.0.0.20", seen_at=_now())]
    runner.invoke(app, ["allow", "aa:11:22:33:44:55", "--name", "Trusted Thing", "--config", str(config_path)])
    result = _scan_with_sightings(config_path, monkeypatch, sightings)
    assert result.exit_code == 0, result.output
    assert "1 of 1 have been reviewed." in result.output or "All devices have been reviewed." in result.output


# --- inspect: active device inspection --------------------------------------


def _fake_inspection(mac="11:22:33:44:55:66", ip="10.0.0.6"):
    from lanfence.models import InspectedPort, InspectionResult

    return InspectionResult(
        mac=mac, ip=ip, method="socket", observed_at=_now(),
        open_ports=[InspectedPort(port=22, service="ssh", banner="OpenSSH 8.9")],
        platform_guess="Linux/Unix-like device (SSH only)", platform_confidence="low",
        platform_reasons=["Open port: 22 (SSH), nothing else responded"],
    )


def test_inspect_unknown_mac_fails(config_path: Path):
    result = runner.invoke(app, ["inspect", "11:22:33:44:55:66", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "no device with mac" in result.output.lower()


def test_inspect_invalid_mac_fails(config_path: Path):
    result = runner.invoke(app, ["inspect", "not-a-mac", "--config", str(config_path)])
    assert result.exit_code == 2


def test_inspect_device_with_no_known_ip_fails(config_path: Path):
    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    store.observe(mac="11:22:33:44:55:66", ip=None, hostname=None, vendor=None, seen_at=_now())
    store.close()

    result = runner.invoke(app, ["inspect", "11:22:33:44:55:66", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "no known ip address" in result.output.lower()


def test_inspect_runs_and_persists_result(config_path: Path):
    _seed_devices(config_path)  # 11:22:33:44:55:66 has ip 10.0.0.6
    fake = _fake_inspection()
    with patch("lanfence.cli.active_inspect.inspect_device", return_value=fake) as inspect_mock:
        result = runner.invoke(app, ["inspect", "11:22:33:44:55:66", "--config", str(config_path)])
    assert result.exit_code == 0, result.output
    inspect_mock.assert_called_once()
    assert inspect_mock.call_args.kwargs.get("use_nmap", True) is True
    assert "Confirmed open ports:" in result.output
    assert "22/tcp" in result.output
    assert "Probable platform: Linux/Unix-like device (SSH only)" in result.output
    assert "not OS fingerprinting" in result.output

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    persisted = store.inspection_for("11:22:33:44:55:66")
    store.close()
    assert persisted == fake


def test_inspect_no_nmap_flag_is_passed_through(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli.active_inspect.inspect_device", return_value=_fake_inspection()) as inspect_mock:
        runner.invoke(app, ["inspect", "11:22:33:44:55:66", "--no-nmap", "--config", str(config_path)])
    assert inspect_mock.call_args.kwargs["use_nmap"] is False


def test_inspect_json_output(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli.active_inspect.inspect_device", return_value=_fake_inspection()):
        result = runner.invoke(app, ["inspect", "11:22:33:44:55:66", "--format", "json", "--config", str(config_path)])
    assert result.exit_code == 0, result.output
    import json as json_module

    payload = json_module.loads(result.output)
    assert payload["mac"] == "11:22:33:44:55:66"
    assert payload["open_ports"][0]["port"] == 22
    assert payload["platform_confidence"] == "low"


def test_inspect_is_never_triggered_by_scan(config_path: Path, monkeypatch):
    from lanfence import scanner as scanner_module

    sightings = [scanner_module.ArpSighting(mac="b8:e9:37:11:22:33", ip="10.0.0.10", seen_at=_now())]
    with patch("lanfence.cli.active_inspect.inspect_device") as inspect_mock:
        _scan_with_sightings(config_path, monkeypatch, sightings)
    inspect_mock.assert_not_called()


# --- review: interactive active-inspection offer -----------------------------


def test_review_interactive_inspect_declined_makes_no_active_probe(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli.active_inspect.inspect_device") as inspect_mock, \
         patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="x\nn\nk\n",
        )
    assert result.exit_code == 0
    assert "sends probe traffic directly to 10.0.0.6" in result.output.lower()
    inspect_mock.assert_not_called()


def test_review_interactive_inspect_accepted_runs_and_shows_result(config_path: Path):
    _seed_devices(config_path)
    fake = _fake_inspection()
    with patch("lanfence.cli.active_inspect.inspect_device", return_value=fake) as inspect_mock, \
         patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="x\ny\nk\n",
        )
    assert result.exit_code == 0
    inspect_mock.assert_called_once()
    assert "Confirmed open ports:" in result.output
    assert "22/tcp" in result.output

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    persisted = store.inspection_for("11:22:33:44:55:66")
    store.close()
    assert persisted == fake


def test_review_interactive_inspect_never_runs_automatically(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli.active_inspect.inspect_device") as inspect_mock, \
         patch("lanfence.cli._stdin_is_interactive", return_value=True):
        runner.invoke(app, ["review", "--config", str(config_path)], input="k\n")
    inspect_mock.assert_not_called()


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


def test_monitor_mdns_ssdp_off_by_default(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--no-passive", "--config", str(config_path)])
    assert "mdns: False" in result.output
    assert "ssdp: False" in result.output


def test_monitor_mdns_flag_is_reflected_in_banner(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    with patch("lanfence.cli.scanner.passive_sniff"):
        result = runner.invoke(app, ["monitor", "--mdns", "--config", str(config_path)])
    assert "mdns: True" in result.output


def test_monitor_ssdp_flag_is_reflected_in_banner(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    with patch("lanfence.cli.scanner.passive_sniff"):
        result = runner.invoke(app, ["monitor", "--ssdp", "--config", str(config_path)])
    assert "ssdp: True" in result.output


def test_monitor_mdns_disabled_when_passive_disabled_even_if_mdns_flag_true(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--mdns", "--no-passive", "--config", str(config_path)])
    assert "mdns: False" in result.output


def test_monitor_warns_when_discovery_enabled_but_passive_disabled(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--mdns", "--no-passive", "--config", str(config_path)])
    assert "enabled but inactive" in result.output.lower()


def test_monitor_no_warning_when_discovery_disabled_and_passive_disabled(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--no-passive", "--config", str(config_path)])
    assert "enabled but inactive" not in result.output.lower()


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


# --- monitor: live dashboard / --live / --no-live --------------------------


def test_monitor_no_live_flag_forces_append_only_output(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--no-live", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "LAN Fence" in result.output  # the existing plain startup banner is preserved
    assert "monitoring (Ctrl+C to stop)" in result.output


def test_monitor_default_is_append_only_when_not_a_tty(config_path: Path, monkeypatch):
    """CliRunner's captured stdout is never a real terminal - default
    (no --live/--no-live given) must behave like --no-live, not hang or
    attempt to open an alternate screen."""

    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "monitoring (Ctrl+C to stop)" in result.output


def test_monitor_explicit_live_on_non_tty_falls_back_with_clear_message(config_path: Path, monkeypatch):
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    result = runner.invoke(app, ["monitor", "--live", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "not an interactive terminal" in result.output.lower()
    # having fallen back, the plain banner still appears - never a half-live, corrupted attempt
    assert "monitoring (Ctrl+C to stop)" in result.output


def test_monitor_shutdown_summary_uses_real_counters(tmp_path: Path, monkeypatch):
    from lanfence import scanner as scanner_module

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "scan": {"resolve_hostnames": False, "passive": False, "scan_interval_seconds": 0.001},
        }),
        encoding="utf-8",
    )

    def fake_active_scan(*, subnet, interface=None, timeout=3.0):
        return [scanner_module.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now())]

    monkeypatch.setattr("lanfence.cli.scanner.active_scan", fake_active_scan)
    monkeypatch.setattr("lanfence.cli.scanner.active_scan_v6", lambda *, interface=None, timeout=3.0: [])
    monkeypatch.setattr("lanfence.cli.scanner.local_subnet", lambda iface=None: "10.0.0.0/24")
    monkeypatch.setattr("lanfence.cli.scanner.default_interface", lambda: "eth0")
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))

    result = runner.invoke(app, ["monitor", "--no-live", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Monitoring stopped after" in result.output
    assert "Seen this session: 1 devices" in result.output
    assert "Newly discovered: 1" in result.output
    assert "Findings: 1" in result.output


def test_monitor_shutdown_summary_findings_count_matches_non_live_printed_findings(tmp_path: Path, monkeypatch):
    """A regression check for the finding counter being wired into
    MonitorStats regardless of live/non-live rendering path."""

    from lanfence import scanner as scanner_module

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "scan": {"resolve_hostnames": False, "passive": False, "scan_interval_seconds": 0.001},
        }),
        encoding="utf-8",
    )

    def fake_active_scan(*, subnet, interface=None, timeout=3.0):
        return [
            scanner_module.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now()),
            scanner_module.ArpSighting(mac="11:22:33:44:55:66", ip="10.0.0.6", seen_at=_now()),
        ]

    monkeypatch.setattr("lanfence.cli.scanner.active_scan", fake_active_scan)
    monkeypatch.setattr("lanfence.cli.scanner.active_scan_v6", lambda *, interface=None, timeout=3.0: [])
    monkeypatch.setattr("lanfence.cli.scanner.local_subnet", lambda iface=None: "10.0.0.0/24")
    monkeypatch.setattr("lanfence.cli.scanner.default_interface", lambda: "eth0")
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))

    result = runner.invoke(app, ["monitor", "--no-live", "--config", str(config_path)])
    printed_finding_lines = result.output.count("] Unknown device connected")
    assert printed_finding_lines == 2
    assert "Findings: 2" in result.output


def test_monitor_live_mode_never_prints_findings_via_old_console_renderer(tmp_path: Path, monkeypatch):
    """In live mode, a finding must reach the activity log, never also (or
    instead) the old bracketed `typer.secho` renderer - avoiding a
    duplicate/console-corrupting print during an active alternate screen."""

    from lanfence import scanner as scanner_module

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(tmp_path / "lanfence.db"),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "scan": {"resolve_hostnames": False, "passive": False, "scan_interval_seconds": 0.001},
        }),
        encoding="utf-8",
    )

    def fake_active_scan(*, subnet, interface=None, timeout=3.0):
        return [scanner_module.ArpSighting(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", seen_at=_now())]

    monkeypatch.setattr("lanfence.cli.scanner.active_scan", fake_active_scan)
    monkeypatch.setattr("lanfence.cli.scanner.active_scan_v6", lambda *, interface=None, timeout=3.0: [])
    monkeypatch.setattr("lanfence.cli.scanner.local_subnet", lambda iface=None: "10.0.0.0/24")
    monkeypatch.setattr("lanfence.cli.scanner.default_interface", lambda: "eth0")
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))
    monkeypatch.setattr("lanfence.cli.monitor_ui.should_use_live", lambda explicit, console: (True, None))

    captured_activity = {}
    from lanfence import monitor_ui as monitor_ui_module

    original_display_init = monitor_ui_module.MonitorDisplay.__init__

    def capturing_init(self, header, activity_log, **kwargs):
        captured_activity["log"] = activity_log
        kwargs["console"] = monitor_ui_module.make_console()
        original_display_init(self, header, activity_log, **kwargs)

    monkeypatch.setattr("lanfence.cli.monitor_ui.MonitorDisplay.__init__", capturing_init)

    result = runner.invoke(app, ["monitor", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "] Unknown device connected" not in result.output
    entries = captured_activity["log"].snapshot()
    assert any("NEW" in e.label for e in entries)


def test_monitor_review_count_matches_is_review_needed(tmp_path: Path, monkeypatch):
    from lanfence.db import DeviceStore

    config_path = tmp_path / "config.yaml"
    db_path = tmp_path / "lanfence.db"
    config_path.write_text(
        yaml.safe_dump({
            "db_path": str(db_path),
            "allowlist_file": str(tmp_path / "allowlist.yaml"),
            "scan": {"passive": False},
        }),
        encoding="utf-8",
    )
    with DeviceStore(db_path) as store:
        store.observe(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5", hostname=None, vendor=None, seen_at=_now())
        store.observe(mac="11:22:33:44:55:66", ip="10.0.0.6", hostname=None, vendor=None, seen_at=_now())
        store.set_investigating("11:22:33:44:55:66", notes="", updated_at=_now())

    monkeypatch.setattr("lanfence.cli.scanner.active_scan", lambda *, subnet, interface=None, timeout=3.0: [])
    monkeypatch.setattr("lanfence.cli.scanner.active_scan_v6", lambda *, interface=None, timeout=3.0: [])
    monkeypatch.setattr("lanfence.cli.scanner.local_subnet", lambda iface=None: "10.0.0.0/24")
    monkeypatch.setattr("lanfence.cli.scanner.default_interface", lambda: "eth0")
    monkeypatch.setattr("lanfence.cli.monitor_ui.should_use_live", lambda explicit, console: (True, None))
    monkeypatch.setattr("lanfence.cli.time.sleep", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt))

    captured = {}
    from lanfence import monitor_ui as monitor_ui_module
    original_update = monitor_ui_module.MonitorDisplay.update

    def capturing_update(self, stats, log, **kwargs):
        captured["stats"] = stats
        return original_update(self, stats, log, **kwargs)

    monkeypatch.setattr("lanfence.cli.monitor_ui.MonitorDisplay.update", capturing_update)

    result = runner.invoke(app, ["monitor", "--config", str(config_path)])
    assert result.exit_code == 0
    # aa:bb:... is untrusted+pending (needs review); 11:22:... is investigating (excluded).
    assert captured["stats"].review == 1
    assert captured["stats"].known == 2


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


# --- services (advertised-service discovery) -------------------------------


def _seed_mdns_service(config_path: Path, *, mac: str | None = "aa:bb:cc:dd:ee:ff") -> None:
    from lanfence.discovery import process_mdns_record_sighting
    from lanfence.discovery import MdnsRecordSighting

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    now = _now()
    if mac is not None:
        store.observe(mac=mac, ip="192.168.1.50", hostname=None, vendor=None, seen_at=now)
    ptr = MdnsRecordSighting(
        rtype="PTR", ttl=120, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
        family="ipv4", seen_at=now, service_type="_ipp._tcp.local", instance_name="Office Printer",
        fq_instance="Office Printer._ipp._tcp.local",
    )
    srv = MdnsRecordSighting(
        rtype="SRV", ttl=120, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
        family="ipv4", seen_at=now, fq_instance="Office Printer._ipp._tcp.local",
        target_host="printer.local", target_port=631,
    )
    addr = MdnsRecordSighting(
        rtype="A", ttl=120, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
        family="ipv4", seen_at=now, address_owner="printer.local", address="192.168.1.50",
    )
    for s in (ptr, srv, addr):
        process_mdns_record_sighting(s, store)
    store.close()


def test_services_empty_result(config_path: Path):
    result = runner.invoke(app, ["services", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "No advertised services observed" in result.output


def test_services_lists_observed_service(config_path: Path):
    _seed_mdns_service(config_path)
    result = runner.invoke(app, ["services", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Printing" in result.output or "_ipp._tcp" in result.output


def test_services_json_output_includes_full_evidence(config_path: Path):
    import json

    _seed_mdns_service(config_path)
    result = runner.invoke(app, ["services", "--format", "json", "--config", str(config_path)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload[0]["target_host"] == "printer.local"
    assert payload[0]["target_port"] == 631
    assert payload[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_services_protocol_filter(config_path: Path):
    import json

    _seed_mdns_service(config_path)
    result = runner.invoke(app, ["services", "--protocol", "ssdp", "--format", "json", "--config", str(config_path)])
    assert result.exit_code == 0
    assert json.loads(result.output) == []


def test_services_rejects_invalid_protocol(config_path: Path):
    result = runner.invoke(app, ["services", "--protocol", "bogus", "--config", str(config_path)])
    assert result.exit_code == 2


def test_services_unassociated_filter_shows_only_unmatched(config_path: Path):
    import json

    _seed_mdns_service(config_path, mac=None)
    result = runner.invoke(
        app, ["services", "--unassociated", "--format", "json", "--config", str(config_path)]
    )
    payload = json.loads(result.output)
    assert len(payload) == 1
    assert payload[0]["mac"] is None


def test_services_include_expired_shows_history(config_path: Path):
    import json

    from lanfence.db import DeviceStore as _Store
    from lanfence.discovery import MdnsRecordSighting, process_mdns_record_sighting

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = _Store(cfg_dict["db_path"])
    ptr = MdnsRecordSighting(
        rtype="PTR", ttl=1, cache_flush=False, interface="eth0", source_ip=None, source_mac=None,
        family="ipv4", seen_at=_now() - timedelta(hours=1), service_type="_ipp._tcp.local",
        instance_name="Old Printer", fq_instance="Old Printer._ipp._tcp.local",
    )
    process_mdns_record_sighting(ptr, store)
    store.close()

    default_result = runner.invoke(app, ["services", "--format", "json", "--config", str(config_path)])
    assert json.loads(default_result.output) == []

    history_result = runner.invoke(
        app, ["services", "--include-expired", "--format", "json", "--config", str(config_path)]
    )
    payload = json.loads(history_result.output)
    assert len(payload) == 1
    assert payload[0]["status"] == "expired"


def test_services_rejects_invalid_format(config_path: Path):
    result = runner.invoke(app, ["services", "--format", "xml", "--config", str(config_path)])
    assert result.exit_code == 2


def test_services_never_scans_or_sends_discovery_traffic(config_path: Path):
    with patch("lanfence.cli.scanner.active_scan") as mock_scan, \
         patch("lanfence.cli.scanner.passive_sniff") as mock_sniff:
        result = runner.invoke(app, ["services", "--config", str(config_path)])
    assert result.exit_code == 0
    mock_scan.assert_not_called()
    mock_sniff.assert_not_called()


def test_device_json_includes_services_key(config_path: Path):
    import json

    _seed_devices(config_path)
    _seed_mdns_service(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--format", "json", "--config", str(config_path)]
    )
    payload = json.loads(result.output)
    assert len(payload["services"]) == 1
    assert payload["services"][0]["target_host"] == "printer.local"


def test_device_table_shows_advertised_services_section(config_path: Path):
    _seed_devices(config_path)
    _seed_mdns_service(config_path)
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Advertised services" in result.output
    assert "printer.local" in result.output


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


# --- device metadata: owner/purpose/group/location --------------------------


def test_device_shows_not_set_for_unset_metadata_by_default(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Owner:      Not set" in result.output


def test_device_set_owner_and_purpose(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--purpose", "Laptop",
              "--config", str(config_path)],
    )
    assert result.exit_code == 0
    assert "metadata for aa:bb:cc:dd:ee:ff updated" in result.output.lower()

    show = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert "Owner:      Alice" in show.output
    assert "Purpose:    Laptop" in show.output


def test_device_metadata_set_persists_across_separate_invocations(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--group", "staff", "--config", str(config_path)])
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--location", "Office", "--config", str(config_path)])
    assert result.exit_code == 0

    show = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert "Group:      staff" in show.output  # still set from the earlier call
    assert "Location:   Office" in show.output


def test_device_clear_metadata_field(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--config", str(config_path)])
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--clear-owner", "--config", str(config_path)])
    assert result.exit_code == 0

    show = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert "Owner:      Not set" in show.output


def test_device_set_and_clear_same_field_is_contradictory(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--clear-owner", "--config", str(config_path)]
    )
    assert result.exit_code == 2
    assert "contradictory" in result.output.lower()


def test_device_rejects_blank_metadata_value(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "   ", "--config", str(config_path)]
    )
    assert result.exit_code == 2
    assert "empty" in result.output.lower()


def test_device_rejects_overlong_metadata_value(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "x" * 200, "--config", str(config_path)]
    )
    assert result.exit_code == 2
    assert "128 characters" in result.output


def test_device_metadata_unknown_mac_fails(config_path: Path):
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--config", str(config_path)]
    )
    assert result.exit_code == 2
    assert "no device" in result.output.lower()


def test_device_metadata_and_presence_can_be_set_in_one_call(config_path: Path):
    _seed_devices(config_path)
    result = runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--presence", "intermittent",
              "--config", str(config_path)],
    )
    assert result.exit_code == 0

    show = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--config", str(config_path)])
    assert "Owner:      Alice" in show.output
    assert "Presence: intermittent" in show.output


def test_device_metadata_json_output_is_additive(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--config", str(config_path)])
    result = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--format", "json", "--config", str(config_path)])
    import json

    payload = json.loads(result.output)
    assert payload["device"]["metadata"]["owner"] == "Alice"
    assert payload["device"]["metadata"]["purpose"] is None


def test_device_metadata_edit_does_not_create_lifecycle_event(config_path: Path):
    _seed_devices(config_path)
    before = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--since", "365d", "--format", "json",
                                  "--config", str(config_path)])
    import json

    before_count = len(json.loads(before.output)["timeline"])
    runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--config", str(config_path)])
    after = runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--since", "365d", "--format", "json",
                                 "--config", str(config_path)])
    after_count = len(json.loads(after.output)["timeline"])

    assert before_count == after_count


def test_devices_owner_filter(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--config", str(config_path)])
    by_mac = _devices_json(config_path, "--owner", "Alice")
    assert set(by_mac) == {"aa:bb:cc:dd:ee:ff"}


def test_devices_owner_filter_is_case_insensitive(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--config", str(config_path)])
    by_mac = _devices_json(config_path, "--owner", "alice")
    assert set(by_mac) == {"aa:bb:cc:dd:ee:ff"}


def test_devices_owner_filter_no_match_is_empty(config_path: Path):
    _seed_devices(config_path)
    by_mac = _devices_json(config_path, "--owner", "Nobody")
    assert by_mac == {}


def test_devices_group_and_location_filters_combine(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(
        app, ["device", "aa:bb:cc:dd:ee:ff", "--group", "staff", "--location", "Office", "--config", str(config_path)]
    )
    runner.invoke(app, ["device", "11:22:33:44:55:66", "--group", "staff", "--config", str(config_path)])

    by_mac = _devices_json(config_path, "--group", "staff", "--location", "Office")
    assert set(by_mac) == {"aa:bb:cc:dd:ee:ff"}


def test_devices_details_flag_shows_metadata_columns(config_path: Path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "200")
    _seed_devices(config_path)
    runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--config", str(config_path)])
    result = runner.invoke(app, ["devices", "--details", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Alice" in result.output
    assert "Owner" in result.output


def test_devices_default_table_omits_metadata_columns(config_path: Path):
    _seed_devices(config_path)
    runner.invoke(app, ["device", "aa:bb:cc:dd:ee:ff", "--owner", "Alice", "--config", str(config_path)])
    result = runner.invoke(app, ["devices", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Alice" not in result.output


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


def test_review_interactive_trust_then_add_device_details(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="t\nNAS\n\nu\ny\nAlice\nLaptop\nstaff\nOffice\n",
        )
    assert result.exit_code == 0
    assert "device details updated" in result.output.lower()

    show = runner.invoke(app, ["device", "11:22:33:44:55:66", "--config", str(config_path)])
    assert "Owner:      Alice" in show.output
    assert "Purpose:    Laptop" in show.output
    assert "Group:      staff" in show.output
    assert "Location:   Office" in show.output


def test_review_interactive_trust_declines_device_details_by_default(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="t\nNAS\n\nu\nn\n",
        )
    assert result.exit_code == 0

    show = runner.invoke(app, ["device", "11:22:33:44:55:66", "--config", str(config_path)])
    assert "Owner:      Not set" in show.output


def test_review_interactive_device_details_aborted_preserves_trust_and_presence(config_path: Path):
    """Exiting the device-details sub-prompt must not undo the trust or
    presence decisions made moments before."""

    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="t\nNAS\n\ni\ny\n",  # confirms "yes, add details" but gives no field input
        )
    assert result.exit_code == 0
    assert "device details unchanged" in result.output.lower()

    listing = runner.invoke(app, ["allow", "--list", "--config", str(config_path)])
    assert "NAS" in listing.output  # trust preserved

    by_mac = _devices_json(config_path)
    assert by_mac["11:22:33:44:55:66"]["presence_policy"] == "intermittent"  # presence preserved


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


def test_review_interactive_shows_compact_dossier_before_the_action_menu(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(app, ["review", "--config", str(config_path)], input="k\n")
    assert result.exit_code == 0
    assert "Device 1 of 1" in result.output
    assert "Likely device:" in result.output
    assert "Actions: [T]rust  [I]nvestigate  [S]nooze  [X] Inspect  [D] Full details  [N]ext  [Q]uit" in result.output


def test_review_interactive_full_details_shows_full_dossier_then_returns_to_menu(config_path: Path):
    _seed_devices(config_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="d\nk\n",
        )
    assert result.exit_code == 0
    # render_device_detail's full-report content, not just the compact glance
    assert "Inventory details" in result.output
    assert "  skipped." in result.output

    cfg_dict = yaml.safe_load(config_path.read_text())
    store = DeviceStore(cfg_dict["db_path"])
    review = store.get_review("11:22:33:44:55:66")
    store.close()
    assert review.state == "pending"  # viewing details makes no decision by itself


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

    # Queue order is by review priority (see lanfence.dossier.review_priority),
    # not MAC order: aa:bb:cc:dd:ee:ff's first octet has the U/L bit set (a
    # locally administered/randomized MAC, the weakest identity evidence -
    # "Priority", rank 1) so it sorts before 11:22:33:44:55:66 (no vendor/
    # hostname at all but a vendor-assigned-looking MAC - "Needs
    # identification", rank 2).
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["review", "--config", str(config_path)],
            input="i\nfirst device flagged\nq\n",
        )
    assert result.exit_code == 0
    assert "stopping review" in result.output.lower()

    store = DeviceStore(cfg_dict["db_path"])
    first_review = store.get_review("aa:bb:cc:dd:ee:ff")
    second_review = store.get_review("11:22:33:44:55:66")
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

    def fake_emit_findings(findings, *, alert, cfg, store, **_kwargs):
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

    def fake_passive_sniff(*, on_sighting, interface=None, stop_event=None, dhcp=True, on_dhcp_server=None, **_kwargs):
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


# --- lanfence channels -------------------------------------------------


def test_channels_bare_listing_empty(tmp_path: Path):
    missing_config = tmp_path / "does-not-exist.yaml"
    result = runner.invoke(app, ["channels", "--config", str(missing_config)])
    assert result.exit_code == 0
    assert "No configuration file at" in result.output
    assert "slack" in result.output
    assert "syslog" in result.output


def test_channels_bare_listing_with_existing_file_shows_no_missing_file_notice(config_path: Path):
    result = runner.invoke(app, ["channels", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "No configuration file at" not in result.output


def test_channels_bare_listing_no_network_calls(config_path: Path):
    with patch("lanfence.channels.urllib.request.urlopen") as mock_urlopen:
        result = runner.invoke(app, ["channels", "--config", str(config_path)])
    assert result.exit_code == 0
    mock_urlopen.assert_not_called()


def test_channels_bare_listing_shows_safe_summary_not_secret(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/services/T000/SECRETSECRET\n"
        "    enabled: true\n"
    )
    result = runner.invoke(app, ["channels", "--config", str(config_path)])
    assert result.exit_code == 0
    # Equality against each whitespace-split token, not any substring/
    # membership check on the rendered output - CodeQL's
    # py/incomplete-url-substring-sanitization rule flags a bare-looking
    # hostname literal used with `in`/`endswith`/`startswith` regardless of
    # what it's checked against, since it can't tell this apart from
    # checking a URL's host for security purposes. `==` isn't a substring
    # operation at all, and is also strictly more precise here: it can't
    # spuriously pass just because "hooks.slack.com" is part of a longer
    # token.
    expected_summary = "hooks.slack.com"
    all_tokens = [word for line in result.output.splitlines() for word in line.split()]
    assert any(word == expected_summary for word in all_tokens)
    assert "SECRETSECRET" not in result.output


def test_channels_setup_requires_interactive_terminal(config_path: Path):
    result = runner.invoke(app, ["channels", "setup", "slack", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "interactive terminal" in result.output.lower()


def test_channels_setup_rejects_unknown_channel(config_path: Path):
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(app, ["channels", "setup", "carrier-pigeon", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "unknown channel" in result.output.lower()


def test_channels_setup_slack_creates_and_saves(config_path: Path):
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "slack", "--config", str(config_path)],
            # webhook_url, timeout(default), enable=y, save=y, digest=n, test=n, another=n
            input="https://hooks.slack.com/services/T000/B000/xxxx\n\ny\ny\nn\nn\nn\n",
        )
    assert result.exit_code == 0
    assert "saved" in result.output.lower()
    assert "restart it" in result.output.lower()

    body = config_path.read_text()
    assert "hooks.slack.com/services/T000/B000/xxxx" in body


def test_channels_setup_no_config_flag_uses_default_path_and_says_so(tmp_path: Path, monkeypatch):
    default_path = tmp_path / "default-config.yaml"
    monkeypatch.setattr("lanfence.channels.DEFAULT_CONFIG_PATH", default_path)
    monkeypatch.setattr("lanfence.cli.DEFAULT_CONFIG_PATH", default_path)
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "slack"],
            input="https://hooks.slack.com/services/x\n\ny\ny\nn\nn\nn\n",
        )
    assert result.exit_code == 0
    assert str(default_path) in result.output
    assert default_path.is_file()


def test_channels_setup_keeps_existing_secret_on_blank(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/services/ORIGINAL\n"
        "    enabled: true\n"
    )
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "slack", "--config", str(config_path)],
            # blank webhook (keep), blank timeout, enable=y(default), save=y, digest=n, test=n, another=n
            input="\n\ny\ny\nn\nn\nn\n",
        )
    assert result.exit_code == 0
    assert "already configured" in result.output.lower()
    assert "ORIGINAL" in config_path.read_text()


def test_channels_setup_clears_secret_with_explicit_clear(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  email:\n    from_addr: lanfence@example.com\n    to_addrs: [ops@example.com]\n"
        "    password: hunter2\n    enabled: false\n"
    )
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "email", "--config", str(config_path)],
            input=(
                "\n"       # smtp_host (keep default localhost)
                "\n"       # smtp_port (keep default)
                "\n"       # use_tls (keep default)
                "\n"       # username (blank, optional)
                "clear\n"  # password -> clear
                "\n"       # from_addr (keep existing)
                "\n"       # to_addrs (keep existing)
                "n\n"      # enable? default False (was False)
                "y\n"      # save
                "n\n"      # digest
                "n\n"      # another channel
            ),
        )
    assert result.exit_code == 0
    body = config_path.read_text()
    assert "hunter2" not in body
    assert "password: null" in body


def test_channels_setup_cancel_before_save_leaves_config_unchanged(config_path: Path):
    original = config_path.read_text()
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "slack", "--config", str(config_path)],
            input="https://hooks.slack.com/services/x\n\ny\nn\n",  # save? -> n
        )
    assert result.exit_code == 0
    assert config_path.read_text() == original


def test_channels_setup_invalid_value_reprompts(config_path: Path):
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "slack", "--config", str(config_path)],
            input=(
                "ftp://not-http\n"   # invalid scheme
                "5\n"                # timeout
                "y\n"                # enable
                "y\n"                # try again? yes
                "https://hooks.slack.com/services/ok\n"
                "5\n"
                "y\n"
                "y\n"                # save
                "n\n"                # digest
                "n\n"                # test
                "n\n"                # another
            ),
        )
    assert result.exit_code == 0
    assert "need fixing" in result.output.lower()
    assert "hooks.slack.com/services/ok" in config_path.read_text()


def test_channels_setup_enabling_incomplete_channel_shows_error_and_can_cancel(config_path: Path):
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "slack", "--config", str(config_path)],
            input=(
                "\n"    # blank webhook_url - no existing value, so left unset
                "5\n"   # timeout
                "y\n"   # enable=yes despite missing webhook_url
                "n\n"   # try again? no -> cancel
            ),
        )
    assert result.exit_code == 0
    assert "cannot enable" in result.output.lower()
    assert not config_path.read_text().count("alerts")


def test_channels_setup_digest_supported_channel_prompts(config_path: Path):
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "slack", "--config", str(config_path)],
            input="https://hooks.slack.com/services/x\n\ny\ny\ny\nn\nn\n",  # digest=y
        )
    assert result.exit_code == 0
    assert "daily digest" in result.output.lower()
    assert "slack" in config_path.read_text()
    body = yaml.safe_load(config_path.read_text())
    assert body["digest"]["channels"] == ["slack"]


def test_channels_setup_twilio_not_offered_digest(config_path: Path):
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "twilio", "--config", str(config_path)],
            input=(
                "AC123\n"             # account_sid
                "tok123\n"            # auth_token
                "+15551234567\n"      # from_number
                "+15559876543\n"      # to_numbers
                "10\n"                # timeout
                "n\n"                 # enable
                "y\n"                 # save
                "n\n"                 # test
                "n\n"                 # another
            ),
        )
    assert result.exit_code == 0
    assert "daily digest" not in result.output.lower()


def test_channels_setup_configure_another_channel_loop(config_path: Path):
    with patch("lanfence.cli._stdin_is_interactive", return_value=True):
        result = runner.invoke(
            app, ["channels", "setup", "--config", str(config_path)],
            input=(
                "1\nslack\n"
                "https://hooks.slack.com/services/x\n\ny\nn\n"
                "1\ndiscord\n"
                "https://discord.com/api/webhooks/x\n\ny\nn\n"
                "save\ny\nn\nn\nexit\n"
            ),
        )
    assert result.exit_code == 0
    # Exact equality on the parsed field, not a substring check on the raw
    # file text - a substring check against a bare-looking hostname like
    # "discord.com" is flagged by CodeQL (py/incomplete-url-substring-
    # sanitization) as the same unsafe pattern used for (incomplete) host
    # allowlisting, even though this is only a test assertion with no
    # security role; asserting the exact stored value sidesteps that
    # while also being a strictly more precise check.
    saved = yaml.safe_load(config_path.read_text())
    assert saved["alerts"]["slack"]["webhook_url"] == "https://hooks.slack.com/services/x"
    assert saved["alerts"]["discord"]["webhook_url"] == "https://discord.com/api/webhooks/x"


def test_channels_setup_test_message_default_is_no(config_path: Path):
    with patch("lanfence.channels.urllib.request.urlopen") as mock_urlopen:
        with patch("lanfence.cli._stdin_is_interactive", return_value=True):
            result = runner.invoke(
                app, ["channels", "setup", "slack", "--config", str(config_path)],
                # accept every default: webhook set explicitly, then blank for
                # everything else including the test-message prompt
                input="https://hooks.slack.com/services/x\n\ny\ny\nn\n\nn\n",
            )
    assert result.exit_code == 0
    mock_urlopen.assert_not_called()


def test_channels_setup_twilio_test_message_warns_about_charges(config_path: Path):
    with patch("lanfence.channels.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b""
        with patch("lanfence.cli._stdin_is_interactive", return_value=True):
            result = runner.invoke(
                app, ["channels", "setup", "twilio", "--config", str(config_path)],
                input=(
                    "AC123\ntok123\n+15551234567\n+15559876543\n10\n"
                    "y\n"    # enable
                    "y\n"    # save
                    "y\n"    # send test? yes
                    "n\n"    # another
                ),
            )
    assert result.exit_code == 0
    assert "charges" in result.output.lower()


def test_channels_enable_requires_complete_config(config_path: Path):
    result = runner.invoke(app, ["channels", "enable", "slack", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "incomplete" in result.output.lower()


def test_channels_enable_unknown_channel(config_path: Path):
    result = runner.invoke(app, ["channels", "enable", "carrier-pigeon", "--config", str(config_path)])
    assert result.exit_code == 2


def test_channels_enable_succeeds_when_complete(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: false\n"
    )
    result = runner.invoke(app, ["channels", "enable", "slack", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "enabled" in result.output.lower()
    assert yaml.safe_load(config_path.read_text())["alerts"]["slack"]["enabled"] is True


def test_channels_disable_preserves_secrets(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  twilio:\n    account_sid: AC1\n    auth_token: tok123\n"
        "    from_number: '+15551234567'\n    to_numbers: ['+15559876543']\n    enabled: true\n"
    )
    result = runner.invoke(app, ["channels", "disable", "twilio", "--config", str(config_path)])
    assert result.exit_code == 0
    body = yaml.safe_load(config_path.read_text())
    assert body["alerts"]["twilio"]["enabled"] is False
    assert body["alerts"]["twilio"]["auth_token"] == "tok123"


def test_channels_disable_preserves_digest_selection_with_note(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: true\n"
        "digest:\n  channels: [slack]\n"
    )
    result = runner.invoke(app, ["channels", "disable", "slack", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "inactive while the channel itself is disabled" in result.output
    body = yaml.safe_load(config_path.read_text())
    assert body["digest"]["channels"] == ["slack"]  # preserved, not cleared


def test_channels_test_requires_enabled(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: false\n"
    )
    result = runner.invoke(app, ["channels", "test", "slack", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "enable slack" in result.output.lower()


def test_channels_test_requires_complete_config(config_path: Path):
    result = runner.invoke(app, ["channels", "test", "slack", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "not fully configured" in result.output.lower()


def test_channels_test_success_uses_real_transport(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: true\n"
    )
    with patch("lanfence.channels.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b""
        result = runner.invoke(app, ["channels", "test", "slack", "--config", str(config_path)])
    assert result.exit_code == 0
    assert mock_urlopen.called
    request = mock_urlopen.call_args[0][0]
    assert request.full_url == "https://hooks.slack.com/x"
    assert b"LAN Fence test message" in request.data


def test_channels_test_failure_nonzero_exit(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: true\n"
    )
    with patch("lanfence.channels.urllib.request.urlopen", side_effect=OSError("refused")):
        result = runner.invoke(app, ["channels", "test", "slack", "--config", str(config_path)])
    assert result.exit_code == 1
    assert "failed" in result.output.lower()


def test_channels_test_does_not_create_device_or_event(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: true\n"
    )
    cfg_dict = yaml.safe_load(config_path.read_text())
    with patch("lanfence.channels.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b""
        runner.invoke(app, ["channels", "test", "slack", "--config", str(config_path)])

    with DeviceStore(cfg_dict["db_path"]) as store:
        assert store.all_devices() == []


def test_channels_test_does_not_touch_alert_cooldowns(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: true\n"
    )
    cfg_dict = yaml.safe_load(config_path.read_text())
    with patch("lanfence.channels.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b""
        runner.invoke(app, ["channels", "test", "slack", "--config", str(config_path)])

    with DeviceStore(cfg_dict["db_path"]) as store:
        row = store._conn.execute("SELECT COUNT(*) AS n FROM alert_log").fetchone()  # noqa: SLF001
        assert row["n"] == 0


def test_channels_malformed_yaml_leaves_file_untouched(config_path: Path):
    original = "not: [valid: yaml: at: all"
    config_path.write_text(original)
    result = runner.invoke(app, ["channels", "--config", str(config_path)])
    assert result.exit_code == 2
    assert config_path.read_text() == original


def test_channels_concurrent_modification_detected_via_enable(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: false\n"
    )

    real_save = __import__("lanfence.channels", fromlist=["save_channels_config_file"]).save_channels_config_file

    def racing_save(loaded, updated_raw):
        # Simulate another process editing the file after this command
        # already loaded it, but before it saves.
        config_path.write_text(config_path.read_text() + "\n# concurrent edit\n")
        return real_save(loaded, updated_raw)

    with patch("lanfence.cli.save_channels_config_file", side_effect=racing_save):
        result = runner.invoke(app, ["channels", "enable", "slack", "--config", str(config_path)])
    assert result.exit_code == 2
    assert "changed on disk" in result.output.lower()


def test_channels_restricts_insecure_permissions_on_save(config_path: Path):
    config_path.chmod(0o644)
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: false\n"
    )
    result = runner.invoke(app, ["channels", "enable", "slack", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "restricted" in result.output.lower()
    import stat

    mode = stat.S_IMODE(config_path.stat().st_mode)
    assert mode == 0o600


def test_channels_validation_and_listing_perform_no_network_calls(config_path: Path):
    config_path.write_text(
        config_path.read_text()
        + "alerts:\n  slack:\n    webhook_url: https://hooks.slack.com/x\n    enabled: true\n"
    )
    with patch("lanfence.channels.urllib.request.urlopen") as mock_urlopen:
        runner.invoke(app, ["channels", "--config", str(config_path)])
        runner.invoke(app, ["channels", "enable", "slack", "--config", str(config_path)])
        runner.invoke(app, ["channels", "disable", "slack", "--config", str(config_path)])
    mock_urlopen.assert_not_called()


def test_monitor_quit_key_uses_clean_shutdown(config_path: Path, monkeypatch):
    monkeypatch.setattr('lanfence.cli.monitor_ui.should_use_live', lambda *args: (True, None))
    monkeypatch.setattr('lanfence.cli.monitor_ui.MonitorDisplay.check_quit',
                        lambda self: (_ for _ in ()).throw(KeyboardInterrupt))
    with patch('lanfence.cli.run_active_sweep') as scan, patch('lanfence.cli.DeviceStore.close') as close:
        result = runner.invoke(app, ['monitor', '--no-passive', '--config', str(config_path)])
    assert result.exit_code == 0
    assert 'Monitoring stopped after' in result.output
    scan.assert_not_called()
    close.assert_called_once()
