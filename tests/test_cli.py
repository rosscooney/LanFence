from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from typer.testing import CliRunner

from lanfence.cli import app

runner = CliRunner()


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


def test_scan_without_permission_reports_error_gracefully(config_path: Path):
    # No root/CAP_NET_RAW in the test environment - scan should degrade to an
    # error message and a clean (empty) result rather than crashing.
    result = runner.invoke(app, ["scan", "--subnet", "192.0.2.0/29", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "No devices responded" in result.stdout or "devices" in result.stdout.lower()


def test_check_reports_ipv6_line(config_path: Path):
    result = runner.invoke(app, ["check", "--config", str(config_path)])
    assert "ipv6:" in result.output


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


def test_config_not_found(tmp_path: Path):
    result = runner.invoke(app, ["allow", "--list", "--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code == 2
