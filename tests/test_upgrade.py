from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from lanfence.cli import (
    _upgrade_command,
    _valid_local_user,
    _version_key,
    app,
)

runner = CliRunner()


def test_version_key_orders_numerically_not_lexically():
    assert _version_key("0.1.1") < _version_key("0.1.10")
    assert _version_key("0.1.10") < _version_key("0.2.0")
    assert _version_key("0.1.1") == _version_key("0.1.1")


def test_valid_local_user_rejects_garbage_and_nonexistent():
    assert _valid_local_user(None) is None
    assert _valid_local_user("; rm -rf /") is None
    assert _valid_local_user("definitely-not-a-real-user-xyz") is None


def test_valid_local_user_accepts_root():
    assert _valid_local_user("root") == "root"


def test_upgrade_command_none_for_editable_install():
    with patch("lanfence.cli._is_editable_install", return_value=True):
        assert _upgrade_command() is None


def test_upgrade_command_pip_for_plain_venv():
    with patch("lanfence.cli._is_editable_install", return_value=False), \
         patch("lanfence.cli._is_pipx_install", return_value=False):
        cmd = _upgrade_command()
    assert cmd[-3:] == ["--upgrade", "--no-cache-dir", "lanfence"]
    assert "pip" in cmd[1] or cmd[1] == "-m"


def test_upgrade_command_pipx_no_sudo_when_not_root():
    with patch("lanfence.cli._is_editable_install", return_value=False), \
         patch("lanfence.cli._is_pipx_install", return_value=True), \
         patch("lanfence.cli._is_root", return_value=False):
        cmd = _upgrade_command()
    assert cmd == ["pipx", "upgrade", "lanfence", "--pip-args=--no-cache-dir"]


def test_upgrade_command_pipx_drops_to_sudo_user_when_root():
    with patch("lanfence.cli._is_editable_install", return_value=False), \
         patch("lanfence.cli._is_pipx_install", return_value=True), \
         patch("lanfence.cli._is_root", return_value=True), \
         patch.dict("os.environ", {"SUDO_USER": "root"}, clear=False), \
         patch("lanfence.cli._valid_local_user", side_effect=lambda n: "alice" if n == "alice" else None), \
         patch("lanfence.cli._path_owner", return_value="alice"):
        cmd = _upgrade_command()
    assert cmd == ["sudo", "-u", "alice", "-H", "pipx", "upgrade", "lanfence", "--pip-args=--no-cache-dir"]


def test_cli_upgrade_reports_up_to_date():
    with patch("lanfence.cli._pypi_latest_version", return_value="0.1.1"), \
         patch("lanfence.cli._is_editable_install", return_value=False), \
         patch("lanfence.cli.__version__", "0.1.1"):
        result = runner.invoke(app, ["upgrade"])
    assert result.exit_code == 0
    assert "up to date" in result.stdout


def test_cli_upgrade_reports_available_with_check_flag():
    with patch("lanfence.cli._pypi_latest_version", return_value="99.0.0"), \
         patch("lanfence.cli._is_editable_install", return_value=False), \
         patch("lanfence.cli._is_pipx_install", return_value=True), \
         patch("lanfence.cli._is_root", return_value=False), \
         patch("lanfence.cli.__version__", "0.1.1"):
        result = runner.invoke(app, ["upgrade", "--check"])
    assert result.exit_code == 10
    assert "99.0.0" in result.stdout
    assert "pipx upgrade lanfence --pip-args=--no-cache-dir" in result.stdout


def test_cli_upgrade_pypi_unreachable():
    with patch("lanfence.cli._pypi_latest_version", return_value=None):
        result = runner.invoke(app, ["upgrade"])
    assert result.exit_code == 1
    assert "could not reach PyPI" in result.output


def test_cli_upgrade_editable_checkout_short_circuits():
    with patch("lanfence.cli._pypi_latest_version", return_value="99.0.0"), \
         patch("lanfence.cli._is_editable_install", return_value=True):
        result = runner.invoke(app, ["upgrade"])
    assert result.exit_code == 0
    assert "git pull" in result.stdout


def test_cli_upgrade_runs_command_and_reports_success():
    fake_result = type("R", (), {"returncode": 0})()
    with patch("lanfence.cli._pypi_latest_version", return_value="99.0.0"), \
         patch("lanfence.cli._is_editable_install", return_value=False), \
         patch("lanfence.cli._is_pipx_install", return_value=True), \
         patch("lanfence.cli._is_root", return_value=False), \
         patch("lanfence.cli.__version__", "0.1.1"), \
         patch("lanfence.cli.subprocess.run", return_value=fake_result) as run_mock:
        result = runner.invoke(app, ["upgrade"])
    assert result.exit_code == 0
    assert "upgraded" in result.stdout
    run_mock.assert_called_once()


def test_cli_upgrade_command_failure_propagates_exit_code():
    fake_result = type("R", (), {"returncode": 7})()
    with patch("lanfence.cli._pypi_latest_version", return_value="99.0.0"), \
         patch("lanfence.cli._is_editable_install", return_value=False), \
         patch("lanfence.cli._is_pipx_install", return_value=True), \
         patch("lanfence.cli._is_root", return_value=False), \
         patch("lanfence.cli.__version__", "0.1.1"), \
         patch("lanfence.cli.subprocess.run", return_value=fake_result):
        result = runner.invoke(app, ["upgrade"])
    assert result.exit_code == 7
    assert "failed" in result.output
