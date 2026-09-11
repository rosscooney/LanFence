from __future__ import annotations

from pathlib import Path

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


def test_config_not_found(tmp_path: Path):
    result = runner.invoke(app, ["allow", "--list", "--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code == 2
